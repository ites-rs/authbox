use async_trait::async_trait;
use std::fmt::Debug;

#[async_trait]
pub trait OneTimeTokenStore {
    type Error: Debug;

    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> Result<(), Self::Error>;
    async fn get(&self, key: &str) -> Result<Option<String>, Self::Error>;
    async fn delete(&self, key: &str) -> Result<(), Self::Error>;
}
