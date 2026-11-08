//! test fixtures for the authbox integration tests: an in-memory user store,
//! a registration dto with extra profile fields, mock email templates, and a
//! helper that wires it all into an `AuthService` backed by redis.
//!
//! tests only. the redis helper expects a server on 127.0.0.1.
#![allow(unused)]

use crate::email_providers::sendgrid_email_provider;
use async_trait::async_trait;
use authbox::prelude::*;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// registration payload. the service only sees email and password through
/// `RegisterUserInput`; the rest is read back in `TestStore::create_user`
/// by downcasting with `as_any`.
#[derive(Clone, Debug, Deserialize)]
pub struct RegisterDto {
    pub email: String,
    pub password: String,

    pub username: Option<String>,
    pub phone: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub age: Option<u32>,
}

impl RegisterUserInput for RegisterDto {
    fn email(&self) -> &str {
        &self.email
    }

    fn password(&self) -> &str {
        &self.password
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// the user we keep in `TestStore`. the password hash is never serialized.
#[derive(Clone, Debug, Serialize)]
pub struct TestUser {
    pub id: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,

    pub is_email_verified: bool,

    pub username: Option<String>,
    pub phone: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub age: Option<u32>,
}

impl AuthUser for TestUser {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn email(&self) -> &str {
        &self.email
    }

    fn password_hash(&self) -> &str {
        &self.password_hash
    }

    fn is_email_verified(&self) -> bool {
        self.is_email_verified
    }

    fn set_email_verified(&mut self, verified: bool) {
        self.is_email_verified = verified;
    }

    fn set_password_hash(&mut self, hash: String) {
        self.password_hash = hash;
    }

    // whole user as json, minus the hash (serde skips it)
    fn extra(&self) -> Option<serde_json::Value> {
        serde_json::to_value(self).ok()
    }
}

fn boxed(u: TestUser) -> Box<dyn AuthUser> {
    Box::new(u)
}

/// in-memory `UserStore`. clones share the same map, so a test can hand one
/// copy to the builder and keep another to look at afterwards.
#[derive(Clone, Default)]
pub struct TestStore {
    pub users: Arc<Mutex<HashMap<String, TestUser>>>,
}

impl TestStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl UserStore for TestStore {
    async fn find_by_id(&self, user_id: &str) -> Result<Option<Box<dyn AuthUser>>, BoxError> {
        Ok(self.users.lock().unwrap().get(user_id).cloned().map(boxed))
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<Box<dyn AuthUser>>, BoxError> {
        let users = self.users.lock().unwrap();
        Ok(users
            .values()
            .find(|u| u.email == email)
            .cloned()
            .map(boxed))
    }

    // the service only normalizes emails for lookups, so the store saves the
    // normalized one itself. duplicate check and insert share one lock, like
    // a UNIQUE index would. errors with "unique violation" on a repeat email.
    async fn create_user(
        &self,
        input: &dyn RegisterUserInput,
        pass_hash: String,
    ) -> Result<Box<dyn AuthUser>, BoxError> {
        let email = input.email().trim().to_lowercase();
        let dto = input.as_any().downcast_ref::<RegisterDto>();

        let mut users = self.users.lock().unwrap();
        if users.values().any(|u| u.email == email) {
            return Err("unique violation".into());
        }

        let user = TestUser {
            id: Uuid::new_v4().to_string(),
            email,
            password_hash: pass_hash,
            is_email_verified: false,

            username: dto.and_then(|d| d.username.clone()),
            phone: dto.and_then(|d| d.phone.clone()),
            country: dto.and_then(|d| d.country.clone()),
            city: dto.and_then(|d| d.city.clone()),
            age: dto.and_then(|d| d.age),
        };

        users.insert(user.id.clone(), user.clone());
        Ok(boxed(user))
    }

    // the service gives us a Box<dyn AuthUser>, which only has the core
    // fields, so we merge those into the stored user instead of replacing it.
    // that way username, phone etc. survive. errors if the id doesn't exist.
    async fn update_user(&self, user: Box<dyn AuthUser>) -> Result<Box<dyn AuthUser>, BoxError> {
        let mut users = self.users.lock().unwrap();
        let existing = users.get_mut(&user.id()).ok_or("user not found")?;

        existing.email = user.email().to_owned();
        existing.password_hash = user.password_hash().to_owned();
        existing.is_email_verified = user.is_email_verified();

        Ok(boxed(existing.clone()))
    }

    async fn delete_user(&self, user_id: &str) -> Result<(), BoxError> {
        self.users.lock().unwrap().remove(user_id);
        Ok(())
    }

    async fn check_email_verified(&self, user_id: &str) -> Result<bool, BoxError> {
        match self.users.lock().unwrap().get(user_id) {
            Some(user) => Ok(user.is_email_verified),
            None => Err("user not found".into()),
        }
    }
}

/// email templates that link to the local dev server on port 8080.
#[derive(Clone)]
pub struct MockTemplates;

impl EmailTemplateConfig for MockTemplates {
    fn verify_email_subject(&self, _user: &dyn AuthUser) -> String {
        "Verify your email".to_string()
    }

    fn verify_email_body(&self, user: &dyn AuthUser, token: &str) -> String {
        format!(
            "Hello {},

Please verify your email by clicking the link below:

http://localhost:8080/verify-email/{}

If you did not create this account, you can ignore this email.",
            user.email(),
            token
        )
    }

    fn reset_password_subject(&self, _user: &dyn AuthUser) -> String {
        "Reset your password".to_string()
    }

    fn reset_password_body(&self, user: &dyn AuthUser, token: &str) -> String {
        format!(
            "Hello {},

You requested a password reset.

Reset your password using the link below:

http://localhost:8080/reset-password/{}

If you did not request this, ignore this email.",
            user.email(),
            token
        )
    }
}

/// builds an `AuthService` for tests: in-memory store, redis for the
/// blacklist and one-time tokens, sendgrid for email, and a memory user cache.
/// needs redis running on 127.0.0.1. the "secret" jwt key is for tests only.
pub async fn build_test_auth() -> Result<AuthService, Box<dyn std::error::Error + Send + Sync>> {
    let client = redis::Client::open("redis://127.0.0.1/")?;

    let auth = AuthService::builder()
        .store(TestStore::new())
        .hasher(DefaultHasher)
        .tokens(DefaultJwtManager::new(
            "test-only-secret-at-least-32-bytes-long!!",
            None,
            None,
        )?)
        .blacklist(RedisBlacklistStore::new(client.clone()).await?)
        .email_sender(sendgrid_email_provider())
        .email_templates(MockTemplates)
        .ott_store(RedisOttStore::new(client))
        .user_cache(DefaultMemoryUserCache::default())
        .build()?;

    Ok(auth)
}
