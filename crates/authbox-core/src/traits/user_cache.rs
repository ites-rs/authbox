use crate::errors::BoxError;
use async_trait::async_trait;

#[async_trait]
pub trait UserCache: Send + Sync {
    async fn get(&self, user_id: &str) -> Result<Option<String>, BoxError>;
    async fn set(
        &self,
        user_id: &str,
        value: &str,
        ttl_seconds: Option<u64>,
    ) -> Result<(), BoxError>;
    async fn invalidate(&self, user_id: &str) -> Result<(), BoxError>;
}
