use async_trait::async_trait;
use authbox_core::traits::OneTimeTokenStore;
use authbox_core::errors::BoxError;
use redis::AsyncCommands;

/// Redis-backed [`OneTimeTokenStore`].
///
/// Tokens are stored as plain string keys with a TTL, so Redis expires
/// them on its own. `take` uses `GETDEL`, which needs **Redis 6.2 or newer**.
#[derive(Clone)]
pub struct RedisOttStore {
    pub client: redis::Client,
}

impl RedisOttStore {
    pub fn new(client: redis::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl OneTimeTokenStore for RedisOttStore {
    /// Store `value` under `key`; Redis removes it after `ttl_seconds`.
    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> Result<(), BoxError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        conn.set_ex::<_, _, ()>(key, value, ttl_seconds).await?;
        Ok(())
    }

    /// Read without consuming. Do NOT use this to redeem a token:
    /// two concurrent callers can both see it. Use [`take`](Self::take).
    async fn get(&self, key: &str) -> Result<Option<String>, BoxError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let value: Option<String> = conn.get(key).await?;
        Ok(value)
    }

    /// Remove a token without reading it. Safe for cleanup/rollback
    /// of a token nobody has received yet (e.g. a failed email send).
    async fn delete(&self, key: &str) -> Result<(), BoxError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        conn.del::<_, ()>(key).await?;
        Ok(())
    }

    /// Atomically read AND delete in one Redis command (`GETDEL`).
    ///
    /// Of any number of concurrent callers with the same key, exactly one
    /// receives `Some(value)`; the rest receive `None`. Use this to redeem
    /// verification and password-reset tokens.
    async fn take(&self, key: &str) -> Result<Option<String>, BoxError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let value: Option<String> = redis::cmd("GETDEL").arg(key).query_async(&mut conn).await?;
        Ok(value)
    }
}