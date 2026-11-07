use crate::types::{Claims, TokenPair};
use crate::errors::BoxError;
use async_trait::async_trait;

#[async_trait]
pub trait TokenManager: Send + Sync {
    async fn generate(&self, user_id: &str) -> Result<TokenPair, BoxError>;
    async fn verify(&self, token: &str) -> Result<Claims, BoxError>;

    /// How long a refresh token lives, in seconds.
    /// Must equal the `exp - iat` you put in refresh tokens in `generate`.
    /// Used to decide how long a "sessions revoked" note must be kept.
    fn refresh_ttl_secs(&self) -> u64;
}

#[async_trait]
pub trait TokenBlacklistStore: Send + Sync {
    async fn is_blacklisted(&self, jti: &str) -> Result<bool, BoxError>;
    async fn blacklist_token(&self, jti: &str, expires_at: i64) -> Result<bool, BoxError>;

    /// Saves, "every token for this user issued at or before `cutoff` is void".
    /// The note can be deleted after 'ttl_seconds`.
    async fn revoke_user_sessions(
        &self,
        user_id: &str,
        cutoff: i64,
        ttl_seconds: u64,
    ) -> Result<(), BoxError>;

    /// Read the note back. None means no sessions have been revoked.
    async fn sessions_revoked_before(&self, user_id: &str) -> Result<Option<i64>, BoxError>;
}
