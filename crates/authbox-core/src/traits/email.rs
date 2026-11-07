use super::auth_user::AuthUser;
use crate::errors::BoxError;
use async_trait::async_trait;

#[async_trait]
pub trait EmailProvider: Send + Sync {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), BoxError>;
}

pub trait EmailTemplateConfig: Send + Sync {
    fn verify_email_subject(&self, user: &dyn AuthUser) -> String;
    fn verify_email_body(&self, user: &dyn AuthUser, token: &str) -> String;
    fn reset_password_subject(&self, user: &dyn AuthUser) -> String;
    fn reset_password_body(&self, user: &dyn AuthUser, token: &str) -> String;
}
