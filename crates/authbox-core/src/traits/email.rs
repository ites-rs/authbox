use super::auth_user::AuthUser;
use async_trait::async_trait;
use std::fmt::Debug;

#[async_trait]
pub trait EmailProvider {
    type Error: Debug;

    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), Self::Error>;
}

#[async_trait]
pub trait EmailTemplateConfig<U: AuthUser> {
    fn verify_email_subject(&self, user: &U) -> String;
    fn verify_email_body(&self, user: &U, token: &str) -> String;
    fn reset_password_subject(&self, user: &U) -> String;
    fn reset_password_body(&self, user: &U, token: &str) -> String;
}
