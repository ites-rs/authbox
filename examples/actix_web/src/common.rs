#![allow(unused)]

use crate::email_providers::sendgrid_email_provider;
use async_trait::async_trait;
use authbox::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use super::email_providers::smtp_email_provider;

// =========================
// REGISTER DTO (MANY FIELDS)
// =========================

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

// =========================
// TRAIT (ONLY AUTH CORE FIELDS)
// =========================

impl RegisterUserInput for RegisterDto {
    fn email(&self) -> &str {
        &self.email
    }

    fn password(&self) -> &str {
        &self.password
    }
}

// =========================
// USER MODEL
// =========================

#[derive(Clone, Debug, Serialize)]
#[allow(unused)]
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

// =========================
// AUTHUSER
// =========================

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
}

// =========================
// STORE
// =========================

#[derive(Clone)]
pub struct TestStore {
    pub users: Arc<Mutex<HashMap<String, TestUser>>>,
}

impl TestStore {
    pub fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl UserStore for TestStore {
    type Error = String;
    type User = TestUser;
    type RegisterDto = RegisterDto;

    async fn find_by_id(&self, user_id: &str) -> Option<TestUser> {
        let users = self.users.lock().unwrap();
        users.get(user_id).cloned()
    }

    async fn find_by_email(&self, email: &str) -> Option<TestUser> {
        let users = self.users.lock().unwrap();
        users.values().find(|u| u.email == email).cloned()
    }

    async fn create_user(
        &self,
        input: RegisterDto,
        pass_hash: String,
    ) -> Result<TestUser, Self::Error> {
        let mut users = self.users.lock().unwrap();

        let user = TestUser {
            id: Uuid::new_v4().to_string(),
            email: input.email,
            password_hash: pass_hash,
            is_email_verified: false,

            username: input.username,
            phone: input.phone,
            country: input.country,
            city: input.city,
            age: input.age,
        };

        users.insert(user.id.clone(), user.clone());

        Ok(user)
    }

    async fn update_user(&self, user: TestUser) -> Result<TestUser, Self::Error> {
        let mut users = self.users.lock().unwrap();
        users.insert(user.id.clone(), user.clone());
        Ok(user)
    }

    async fn delete_user(&self, user_id: &str) -> Result<(), Self::Error> {
        let mut users = self.users.lock().unwrap();
        users.remove(user_id);
        Ok(())
    }

    async fn check_email_verified(&self, user_id: &str) -> Result<bool, Self::Error> {
        let users = self.users.lock().unwrap();

        match users.get(user_id) {
            Some(user) => Ok(user.is_email_verified),
            None => Err("user not found".to_string()),
        }
    }
}

// =========================
// EMAIL TEMPLATES
// =========================
#[derive(Clone)]
pub struct MockTemplates;

impl EmailTemplateConfig<TestUser> for MockTemplates {
    fn verify_email_subject(&self, _: &TestUser) -> String {
        "Verify your email".to_string()
    }

    fn verify_email_body(&self, user: &TestUser, token: &str) -> String {
        format!(
            "Hello {},

Please verify your email by clicking the link below:

http://localhost:8080/verify-email/{}

If you did not create this account, you can ignore this email.",
            user.email, token
        )
    }

    fn reset_password_subject(&self, _: &TestUser) -> String {
        "Reset your password".to_string()
    }

    fn reset_password_body(&self, user: &TestUser, token: &str) -> String {
        format!(
            "Hello {},

You requested a password reset.

Reset your password using the link below:

http://localhost:8080/reset-password/{}

If you did not request this, ignore this email.",
            user.email, token
        )
    }
}
// =========================
// TEST AUTH SERVICE TYPE
// =========================

pub type TestAuthService = AuthService<
    TestStore,
    DefaultHasher,
    DefaultJwtManager,
    RedisBlacklistStore,
    SendGridEmailProvider,
    MockTemplates,
    RedisOttStore,
>;

pub fn build_test_auth() -> TestAuthService {
    let client = redis::Client::open("redis://127.0.0.1/").expect("failed to connect to redis");

    AuthService::builder()
        .store(TestStore::new())
        .hasher(DefaultHasher)
        .tokens(DefaultJwtManager::new("secret"))
        .blacklist(RedisBlacklistStore::new(client.clone()))
        .email_sender(sendgrid_email_provider())
        .email_templates(MockTemplates)
        .ott_store(RedisOttStore::new(client))
        .build()
}
