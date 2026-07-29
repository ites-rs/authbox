use super::auth_user::AuthUser;
use super::register_user::RegisterUserInput;
use async_trait::async_trait;
use std::fmt::Debug;

#[async_trait]
pub trait UserStore {
    type Error: Debug;
    type User: AuthUser;
    type RegisterDto: RegisterUserInput;

    async fn find_by_id(&self, user_id: &str) -> Option<Self::User>;
    async fn find_by_email(&self, email: &str) -> Option<Self::User>;
    async fn create_user(
        &self,
        input: Self::RegisterDto,
        pass_hash: String,
    ) -> Result<Self::User, Self::Error>;
    async fn update_user(&self, user: Self::User) -> Result<Self::User, Self::Error>;
    async fn delete_user(&self, user_id: &str) -> Result<(), Self::Error>;
    async fn check_email_verified(&self, user_id: &str) -> Result<bool, Self::Error>;
}
