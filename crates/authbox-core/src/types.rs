use super::traits::BlacklistableClaims;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    Access,
    Refresh,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub jti: String,
    pub exp: i64,
    pub iat: i64,
    pub typ: TokenType,
}

impl BlacklistableClaims for Claims {
    fn jti(&self) -> &str {
        &self.jti
    }
    fn exp(&self) -> i64 {
        self.exp
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: usize,
    pub token_type: String, // "Bearer"
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Me {
    pub id: String,
    pub email: String,
    pub email_verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

impl Me {
    pub fn new(
        id: impl Into<String>,
        email: impl Into<String>,
        email_verified: bool,
        extra: Option<serde_json::Value>,
    ) -> Self {
        Self {
            id: id.into(),
            email: email.into(),
            email_verified,
            extra,
        }
    }
}
