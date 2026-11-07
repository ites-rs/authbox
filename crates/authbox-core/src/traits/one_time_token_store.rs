use crate::errors::BoxError;
use async_trait::async_trait;

#[async_trait]
pub trait OneTimeTokenStore: Send + Sync {
    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> Result<(), BoxError>;
    async fn get(&self, key: &str) -> Result<Option<String>, BoxError>;
    async fn delete(&self, key: &str) -> Result<(), BoxError>;
    async fn take(&self, key: &str) -> Result<Option<String>, BoxError>;
}
