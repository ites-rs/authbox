/// Replaces every `type Error: Debug`. Any `std::error::Error + Send + Sync`
/// converts into it with `?`, so implementors just write `Ok(db.query().await?)`.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("email not verified")]
    EmailNotVerified,
    #[error("email already exists")]
    EmailAlreadyExists,
    #[error("email already verified")]
    EmailAlreadyVerified,
    #[error("user not found")]
    NotFound,
    #[error("invalid token")]
    InvalidToken,
    #[error("token revoked")]
    BlacklistedToken,
    #[error("missing bearer token")]
    MissingToken,
    #[error("password must be between {min} and {max} characters")]
    PasswordLength { min: usize, max: usize },
    #[error("too many requests")]
    RateLimited,

    #[error("store error")]
    Store(#[source] BoxError),
    #[error("cache error")]
    Cache(#[source] BoxError),
    #[error("token error")]
    Token(#[source] BoxError),
    #[error("blacklist error")]
    Blacklist(#[source] BoxError),
    #[error("email error")]
    Email(#[source] BoxError),
    #[error("one-time-token error")]
    Ott(#[source] BoxError),
    #[error("internal error")]
    Internal(#[source] BoxError),
}

impl AuthError {
    pub fn password_length() -> Self {
        Self::PasswordLength { min: 12, max: 128 }
    }

    pub fn status(&self) -> u16 {
        match self {
            Self::PasswordLength { .. } => 400,
            Self::InvalidCredentials
            | Self::InvalidToken
            | Self::BlacklistedToken
            | Self::MissingToken => 401,
            Self::EmailNotVerified => 403,
            Self::NotFound => 404,
            Self::EmailAlreadyExists | Self::EmailAlreadyVerified => 409,
            Self::RateLimited => 429,
            _ => 500,
        }
    }

    /// Safe to send to clients (hides backend details on 500s).
    pub fn public_message(&self) -> String {
        if self.status() == 500 {
            "internal error".into()
        } else {
            self.to_string()
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("missing component: {0}")]
    Missing(&'static str),
}

/// Parses `Authorization: Bearer <token>`. Shared by every adapter.
pub fn bearer_token(header: Option<&str>) -> Result<&str, AuthError> {
    header
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or(AuthError::MissingToken)
}
