use async_trait::async_trait;
use authbox_core::prelude::{BoxError, UserCache};
use moka::future::Cache;
use std::time::Duration;

#[derive(Clone)]
pub struct DefaultMemoryUserCache {
    inner: Cache<String, String>,
}

impl DefaultMemoryUserCache {
    pub fn new(max_entries: u64, ttl: Duration) -> Self {
        Self {
            inner: Cache::builder()
                .max_capacity(max_entries)
                .time_to_live(ttl)
                .build(),
        }
    }
}

impl Default for DefaultMemoryUserCache {
    /// 10,000 users, 60 seconds
    fn default() -> Self {
        Self::new(10_000, Duration::from_secs(60))
    }
}

#[async_trait]
impl UserCache for DefaultMemoryUserCache {
    async fn get(&self, user_id: &str) -> Result<Option<String>, BoxError> {
        Ok(self.inner.get(user_id).await)
    }
    async fn set(
        &self,
        user_id: &str,
        value: &str,
        _ttl_seconds: Option<u64>,
    ) -> Result<(), BoxError> {
        self.inner
            .insert(user_id.to_owned(), value.to_owned())
            .await;
        Ok(())
    }
    async fn invalidate(&self, user_id: &str) -> Result<(), BoxError> {
        self.inner.invalidate(user_id).await;
        Ok(())
    }
}
