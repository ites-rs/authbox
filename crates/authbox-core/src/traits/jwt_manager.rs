use async_trait::async_trait;
use std::fmt::Debug;

#[async_trait]
pub trait TokenManager {
    type Token;
    type Claims: 'static;
    type Error: Debug;

    async fn generate(&self, user_id: &str) -> Result<Self::Token, Self::Error>;
    async fn verify(&self, token: &str) -> Result<Self::Claims, Self::Error>;
    async fn refresh(&self, refresh_token: &str) -> Result<Self::Token, Self::Error>;
}

#[async_trait]
pub trait TokenBlacklistStore {
    type Error: Debug;

    async fn is_blacklisted(&self, jti: &str) -> Result<bool, Self::Error>;
    async fn blacklist_token(&self, jti: &str, expires_at: i64) -> Result<bool, Self::Error>;
}
