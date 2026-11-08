use async_trait::async_trait;
use authbox_core::prelude::{BoxError, Claims, TokenManager, TokenPair, TokenType};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use std::time::Duration;
use uuid::Uuid;

const MIN_SECRET_BYTES: usize = 32;

const DEFAULT_ACCESS: Duration = Duration::from_secs(60 * 15); // 15 minutes
const DEFAULT_REFRESH: Duration = Duration::from_secs(60 * 60 * 24 * 7); // 7 days

const MIN_ACCESS: Duration = Duration::from_secs(60); // 1 minute
const MAX_ACCESS: Duration = Duration::from_secs(60 * 60); // 1 hour
const MAX_REFRESH: Duration = Duration::from_secs(60 * 60 * 24 * 90); // 90 days

#[derive(Clone)]
pub struct DefaultJwtManager {
    encoding: EncodingKey,
    decoding: DecodingKey,
    access_ttl_secs: u64,
    refresh_ttl_secs: u64,
}

impl DefaultJwtManager {
    /// `None` for a TTL means "use the default" (access 15 min, refresh 7 days).
    pub fn new<T: AsRef<[u8]>>(
        secret: T,
        access_ttl: Option<Duration>,
        refresh_ttl: Option<Duration>,
    ) -> Result<Self, BoxError> {
        let secret = secret.as_ref();
        let access = access_ttl.unwrap_or(DEFAULT_ACCESS);
        let refresh = refresh_ttl.unwrap_or(DEFAULT_REFRESH);

        if secret.len() < MIN_SECRET_BYTES {
            return Err(format!("JWT secret must be at least {MIN_SECRET_BYTES} bytes").into());
        }
        if access < MIN_ACCESS || access > MAX_ACCESS {
            return Err("access TTL must be between 1 minute and 1 hour".into());
        }
        if refresh > MAX_REFRESH {
            return Err("refresh TTL must be at most 90 days".into());
        }
        if refresh <= access {
            return Err("refresh TTL must be longer than access TTL".into());
        }

        Ok(Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
            access_ttl_secs: access.as_secs(),
            refresh_ttl_secs: refresh.as_secs(),
        })
    }

    fn make_token(&self, user_id: &str, typ: TokenType, ttl_secs: u64) -> Result<String, BoxError> {
        let now = Utc::now().timestamp();
        let claims = Claims {
            sub: user_id.to_owned(),
            jti: Uuid::new_v4().to_string(),
            iat: now,
            exp: now + ttl_secs as i64,
            typ,
        };
        Ok(encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &self.encoding,
        )?)
    }
}

#[async_trait]
impl TokenManager for DefaultJwtManager {
    async fn generate(&self, user_id: &str) -> Result<TokenPair, BoxError> {
        let access_token = self.make_token(user_id, TokenType::Access, self.access_ttl_secs)?;
        let refresh_token = self.make_token(user_id, TokenType::Refresh, self.refresh_ttl_secs)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in: self.access_ttl_secs as usize,
            token_type: "Bearer".to_string(),
        })
    }

    async fn verify(&self, token: &str) -> Result<Claims, BoxError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = 5;
        validation.set_required_spec_claims(&["exp", "sub"]);

        Ok(decode::<Claims>(token, &self.decoding, &validation)?.claims)
    }

    fn refresh_ttl_secs(&self) -> u64 {
        self.refresh_ttl_secs
    }
}
