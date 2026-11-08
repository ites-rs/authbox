use async_trait::async_trait;
use authbox_core::prelude::{BoxError, TokenBlacklistStore};
use redis::aio::ConnectionManager;
use std::time::{SystemTime, UNIX_EPOCH};

const BLACKLIST_PREFIX: &str = "blacklist";
const REVOKED_BEFORE_PREFIX: &str = "revoked_before";

#[derive(Clone)]
pub struct RedisBlacklistStore {
    conn: ConnectionManager,
}

impl RedisBlacklistStore {
    /// ConnectionManager reconnects automatically and is cheap to clone.
    pub async fn new(client: redis::Client) -> Result<Self, BoxError> {
        let conn = ConnectionManager::new(client).await?;
        Ok(Self { conn })
    }
}

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before 1970")
        .as_secs() as i64
}

#[async_trait]
impl TokenBlacklistStore for RedisBlacklistStore {
    async fn is_blacklisted(&self, jti: &str) -> Result<bool, BoxError> {
        let mut conn = self.conn.clone();
        let exists: bool = redis::cmd("EXISTS")
            .arg(format!("{BLACKLIST_PREFIX}:{jti}"))
            .query_async(&mut conn)
            .await?;
        Ok(exists)
    }

    /// true  = this call blacklisted it
    /// false = it was already blacklisted (someone else won the race)
    async fn blacklist_token(&self, jti: &str, expires_at: i64) -> Result<bool, BoxError> {
        let now = now_unix_secs();

        // already expired: verify() rejects it anyway, nothing to store
        if expires_at <= now {
            return Ok(true);
        }
        let ttl = (expires_at - now) as u64;

        let mut conn = self.conn.clone();
        // SET key 1 NX EX ttl -> "OK" if newly set, nil if the key already existed
        let set: Option<String> = redis::cmd("SET")
            .arg(format!("{BLACKLIST_PREFIX}:{jti}"))
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(ttl)
            .query_async(&mut conn)
            .await?;

        Ok(set.is_some())
    }

    async fn revoke_user_sessions(
        &self,
        user_id: &str,
        cutoff: i64,
        ttl_seconds: u64,
    ) -> Result<(), BoxError> {
        let mut conn = self.conn.clone();
        let _: () = redis::cmd("SET")
            .arg(format!("{REVOKED_BEFORE_PREFIX}:{user_id}"))
            .arg(cutoff)
            .arg("EX")
            .arg(ttl_seconds.max(1)) // Redis rejects an EX of 0
            .query_async(&mut conn)
            .await?;
        Ok(())
    }

    async fn sessions_revoked_before(&self, user_id: &str) -> Result<Option<i64>, BoxError> {
        let mut conn = self.conn.clone();
        let cutoff: Option<i64> = redis::cmd("GET")
            .arg(format!("{REVOKED_BEFORE_PREFIX}:{user_id}"))
            .query_async(&mut conn)
            .await?;
        Ok(cutoff)
    }
}