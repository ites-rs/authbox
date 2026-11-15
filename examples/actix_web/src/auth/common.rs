// Everything needed to wire up and test the auth service:
// the in-memory store, registration DTO, mock email templates,
// all three email provider builders, and build_test_auth.
#![allow(unused)]

use async_trait::async_trait;
use authbox::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    any::Any,
    collections::HashMap,
    env,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Registration DTO
// ---------------------------------------------------------------------------

/// The JSON body for POST /register. The service only reads email and
/// password through `RegisterUserInput`; the extra fields are pulled back
/// in `TestStore::create_user` by downcasting with `as_any`.
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

// ---------------------------------------------------------------------------
// In-memory user
// ---------------------------------------------------------------------------

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
    fn set_email_verified(&mut self, v: bool) {
        self.is_email_verified = v;
    }
    fn set_password_hash(&mut self, h: String) {
        self.password_hash = h;
    }
    fn extra(&self) -> Option<serde_json::Value> {
        serde_json::to_value(self).ok()
    }
}

fn boxed(u: TestUser) -> Box<dyn AuthUser> {
    Box::new(u)
}

// ---------------------------------------------------------------------------
// In-memory store
// ---------------------------------------------------------------------------

/// Clones share the same underlying map, so a test can pass one copy to the
/// builder and keep another to inspect results.
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
    async fn find_by_id(&self, id: &str) -> Result<Option<Box<dyn AuthUser>>, BoxError> {
        Ok(self.users.lock().unwrap().get(id).cloned().map(boxed))
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<Box<dyn AuthUser>>, BoxError> {
        Ok(self
            .users
            .lock()
            .unwrap()
            .values()
            .find(|u| u.email == email)
            .cloned()
            .map(boxed))
    }

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

    // merges core fields back into the stored record so the extra profile
    // fields (username, phone, etc.) survive an update
    async fn update_user(&self, user: Box<dyn AuthUser>) -> Result<Box<dyn AuthUser>, BoxError> {
        let mut users = self.users.lock().unwrap();
        let existing = users.get_mut(&user.id()).ok_or("user not found")?;
        existing.email = user.email().to_owned();
        existing.password_hash = user.password_hash().to_owned();
        existing.is_email_verified = user.is_email_verified();
        Ok(boxed(existing.clone()))
    }

    async fn delete_user(&self, id: &str) -> Result<(), BoxError> {
        self.users.lock().unwrap().remove(id);
        Ok(())
    }

    async fn check_email_verified(&self, id: &str) -> Result<bool, BoxError> {
        self.users
            .lock()
            .unwrap()
            .get(id)
            .map(|u| u.is_email_verified)
            .ok_or_else(|| "user not found".into())
    }
}

// ---------------------------------------------------------------------------
// Mock email templates
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct MockTemplates;

impl EmailTemplateConfig for MockTemplates {
    fn verify_email_subject(&self, _user: &dyn AuthUser) -> String {
        "Verify your email".into()
    }

    fn verify_email_body(&self, user: &dyn AuthUser, token: &str) -> String {
        println!("[verify token] {token}");
        format!(
            "Hi {},\n\nVerify here: http://localhost:8080/verify-email/{}\n\nIgnore if you didn't sign up.",
            user.email(),
            token
        )
    }

    fn reset_password_subject(&self, _user: &dyn AuthUser) -> String {
        "Reset your password".into()
    }

    fn reset_password_body(&self, user: &dyn AuthUser, token: &str) -> String {
        println!("[reset token] {token}");
        format!(
            "Hi {},\n\nReset here: http://localhost:8080/reset-password/{}\n\nIgnore if you didn't request this.",
            user.email(),
            token
        )
    }
}

// ---------------------------------------------------------------------------
// Email providers
// ---------------------------------------------------------------------------

pub fn resend_email_provider() -> ResendEmailProvider {
    ResendEmailProvider::new(
        env::var("RESEND_API_KEY").expect("RESEND_API_KEY missing"),
        env::var("RESEND_FROM_EMAIL").expect("RESEND_FROM_EMAIL missing"),
    )
}

pub fn sendgrid_email_provider() -> SendGridEmailProvider {
    SendGridEmailProvider::new(
        env::var("SENDGRID_API_KEY").expect("SENDGRID_API_KEY missing"),
        env::var("SENDGRID_FROM_EMAIL").expect("SENDGRID_FROM_EMAIL missing"),
        env::var("SENDGRID_FROM_NAME").expect("SENDGRID_FROM_NAME missing"),
    )
}

pub fn smtp_email_provider() -> SmtpEmailProvider {
    SmtpEmailProvider::new(
        &env::var("SMTP_HOST").expect("SMTP_HOST missing"),
        &env::var("SMTP_USERNAME").expect("SMTP_USERNAME missing"),
        &env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD missing"),
        &env::var("SMTP_FROM_EMAIL").expect("SMTP_FROM_EMAIL missing"),
    )
}

// ---------------------------------------------------------------------------
// Auth service builder
// ---------------------------------------------------------------------------

pub async fn build_test_auth() -> Result<AuthService, Box<dyn std::error::Error + Send + Sync>> {
    let client = redis::Client::open("redis://127.0.0.1/")?;

    Ok(AuthService::builder()
        .store(TestStore::new())
        .hasher(DefaultHasher)
        .tokens(DefaultJwtManager::new(
            "test-only-secret-at-least-32-bytes-long!!",
            None,
            None,
        )?)
        .blacklist(RedisBlacklistStore::new(client.clone()).await?)
        .email_sender(resend_email_provider())
        .email_templates(MockTemplates)
        .ott_store(RedisOttStore::new(client))
        .user_cache(DefaultMemoryUserCache::default())
        .build()?)
}
