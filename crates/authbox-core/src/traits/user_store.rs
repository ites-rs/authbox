use super::auth_user::AuthUser;
use super::register_user::RegisterUserInput;
use crate::errors::BoxError;
use async_trait::async_trait;

#[async_trait]
pub trait UserStore: Send + Sync {
    async fn find_by_id(&self, user_id: &str) -> Result<Option<Box<dyn AuthUser>>, BoxError>;
    async fn find_by_email(&self, email: &str) -> Result<Option<Box<dyn AuthUser>>, BoxError>;
    async fn create_user(
        &self,
        input: &dyn RegisterUserInput,
        pass_hash: String,
    ) -> Result<Box<dyn AuthUser>, BoxError>;
    async fn update_user(&self, user: Box<dyn AuthUser>) -> Result<Box<dyn AuthUser>, BoxError>;
    async fn delete_user(&self, user_id: &str) -> Result<(), BoxError>;
    async fn check_email_verified(&self, user_id: &str) -> Result<bool, BoxError>;
}
