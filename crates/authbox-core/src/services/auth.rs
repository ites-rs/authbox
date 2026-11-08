use crate::configs::AuthServiceBuilder;
use crate::errors::AuthError;
use crate::traits::*;
use crate::types::{Claims, Me, TokenPair, TokenType};
use std::sync::Arc;
use tracing::warn;
use tracing::{error, info};
use uuid::Uuid;

const VERIFY: &str = "verify";
const RESET: &str = "reset";
const VERIFY_TTL: u64 = 60 * 60 * 24;
const RESET_TTL: u64 = 60 * 15;
const M_CACHE_HITS: &str = "authbox_cache_hits_total";
const M_CACHE_MISSES: &str = "authbox_cache_misses_total";
const M_CACHE_READ_FAIL: &str = "authbox_cache_read_failures_total";
const M_CACHE_WRITE_FAIL: &str = "authbox_cache_write_failures_total";
const M_CACHE_INVALIDATE_FAIL: &str = "authbox_cache_invalidate_failures_total";

pub(crate) struct Inner {
    pub(crate) store: Box<dyn UserStore>,
    pub(crate) hasher: Box<dyn PasswordHasher>,
    pub(crate) tokens: Box<dyn TokenManager>,
    pub(crate) blacklist: Box<dyn TokenBlacklistStore>,
    pub(crate) email_sender: Box<dyn EmailProvider>,
    pub(crate) email_templates: Box<dyn EmailTemplateConfig>,
    pub(crate) ott_store: Box<dyn OneTimeTokenStore>,
    pub(crate) cache: Option<Box<dyn UserCache>>,
    /// verified against for unknown emails so login timing doesn't leak accounts
    pub(crate) dummy_hash: String,
}

#[derive(Clone)]
pub struct AuthService {
    pub(crate) inner: Arc<Inner>,
}

impl AuthService {
    pub fn builder() -> AuthServiceBuilder {
        AuthServiceBuilder::default()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        store: Box<dyn UserStore>,
        hasher: Box<dyn PasswordHasher>,
        tokens: Box<dyn TokenManager>,
        blacklist: Box<dyn TokenBlacklistStore>,
        email_sender: Box<dyn EmailProvider>,
        email_templates: Box<dyn EmailTemplateConfig>,
        ott_store: Box<dyn OneTimeTokenStore>,
        cache: Option<Box<dyn UserCache>>,
    ) -> Self {
        let dummy_hash = hasher.hash(&Uuid::new_v4().to_string());

        Self {
            inner: Arc::new(Inner {
                store,
                hasher,
                tokens,
                blacklist,
                email_sender,
                email_templates,
                ott_store,
                cache,
                dummy_hash,
            }),
        }
    }

    async fn hash_password(&self, password: String) -> Result<String, AuthError> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || inner.hasher.hash(&password))
            .await
            .map_err(|e| AuthError::Internal(Box::new(e)))
    }

    async fn verify_password(&self, password: String, hash: String) -> Result<bool, AuthError> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || inner.hasher.verify(&password, &hash))
            .await
            .map_err(|e| AuthError::Internal(Box::new(e)))
    }

    /// checks signature + expiry + token type + blacklist + session cutoff
    async fn check(&self, token: &str, expected: TokenType) -> Result<Claims, AuthError> {
        let auth_service = &self.inner;
        let claims = auth_service
            .tokens
            .verify(token)
            .await
            .map_err(|_| AuthError::InvalidToken)?;

        if claims.typ != expected {
            return Err(AuthError::InvalidToken);
        }
        if auth_service
            .blacklist
            .is_blacklisted(claims.jti())
            .await
            .map_err(AuthError::Blacklist)?
        {
            return Err(AuthError::BlacklistedToken);
        }

        // all of this user's sessions revoked after this token was issued?
        if let Some(cutoff) = auth_service
            .blacklist
            .sessions_revoked_before(&claims.sub)
            .await
            .map_err(AuthError::Blacklist)?
            && claims.iat <= cutoff
        {
            return Err(AuthError::InvalidToken);
        }

        Ok(claims)
    }

    async fn rollback_user(&self, user_id: &str) {
        if let Err(e) = self.inner.store.delete_user(user_id).await {
            error!(user_id = %user_id, error = ?e, "Failed to roll back created user");
        }
        if let Err(e) = self.invalidate_user_cache(user_id).await {
            error!(user_id = %user_id, error = ?e, "Failed to invalidate cache during rollback");
        }
    }

    pub async fn invalidate_user_cache(&self, user_id: &str) -> Result<(), AuthError> {
        match &self.inner.cache {
            Some(cache) => cache.invalidate(user_id).await.map_err(|e| {
                metrics::counter!(M_CACHE_INVALIDATE_FAIL).increment(1);
                AuthError::Cache(e)
            }),
            None => Ok(()),
        }
    }

    fn check_password_length(password: &str) -> Result<&str, AuthError> {
        let n = password.chars().count();
        if (12..=128).contains(&n) {
            Ok(password)
        } else {
            Err(AuthError::password_length())
        }
    }

    fn normalize_email(email: &str) -> String {
        email.trim().to_lowercase()
    }

    /// verification and reset tokens can no longer be swapped for each other
    fn ott_key(purpose: &str, token: &str) -> String {
        format!("{purpose}:{token}")
    }

    /// current time in unix SECONDS (same unit as `iat` in Claims)
    fn now_unix_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before 1970")
            .as_secs() as i64
    }

    /// Register a new user account.
    ///
    /// The `find_by_email` check below is only a fast path. It is NOT safe on
    /// its own: two simultaneous signups can both pass it. Your database MUST
    /// have a UNIQUE index on the (normalized) email column, and
    /// `UserStore::create_user` MUST map a unique-violation error to
    /// `AuthError::EmailAlreadyExists` (see `map_store_create_err`).
    pub async fn register(
        &self,
        input: &dyn RegisterUserInput,
    ) -> Result<Box<dyn AuthUser>, AuthError> {
        let password = Self::check_password_length(input.password())?;
        let auth_service = &self.inner;

        if auth_service
            .store
            .find_by_email(&Self::normalize_email(input.email()))
            .await
            .map_err(AuthError::Store)?
            .is_some()
        {
            return Err(AuthError::EmailAlreadyExists);
        }

        let hash = self.hash_password(password.to_owned()).await?;

        let user = auth_service
            .store
            .create_user(input, hash)
            .await
            .map_err(Self::map_store_create_err)?;
        let user_id = user.id();

        let token = Uuid::new_v4().to_string();
        let key = Self::ott_key(VERIFY, &token);

        if let Err(err) = auth_service.ott_store.set(&key, &user_id, VERIFY_TTL).await {
            self.rollback_user(&user_id).await;
            return Err(AuthError::Ott(err));
        }

        let subject = auth_service
            .email_templates
            .verify_email_subject(user.as_ref());
        let body = auth_service
            .email_templates
            .verify_email_body(user.as_ref(), &token);

        info!(user_id = %user_id, "Sending verification email");

        if let Err(err) = auth_service
            .email_sender
            .send_email(user.email(), &subject, &body)
            .await
        {
            error!(user_id = %user_id, error = ?err,
                   "Failed to send verification email");

            if let Err(e) = auth_service.ott_store.delete(&key).await {
                error!(error = ?e, "Failed to roll back verification token");
            }
            self.rollback_user(&user_id).await;
            return Err(AuthError::Email(err));
        }

        info!(user_id = %user_id, "Verification email sent successfully");
        Ok(user)
    }

    /// Maps an error from `UserStore::create_user` to an `AuthError`.
    ///
    /// TODO: replace the body with a check for YOUR store's unique-violation
    /// error, e.g. for sqlx + Postgres:
    ///
    /// ```ignore
    /// if let Some(db) = e.downcast_ref::<sqlx::Error>()
    ///     .and_then(|e| e.as_database_error())
    /// {
    ///     if db.is_unique_violation() {
    ///         return AuthError::EmailAlreadyExists;
    ///     }
    /// }
    /// ```
    ///
    /// Alternatively, have your store return `AuthError::EmailAlreadyExists`
    /// wrapped in the BoxError and downcast it here.
    fn map_store_create_err(e: crate::errors::BoxError) -> AuthError {
        if let Some(AuthError::EmailAlreadyExists) = e.downcast_ref::<AuthError>() {
            return AuthError::EmailAlreadyExists;
        }
        AuthError::Store(e)
    }

    /// Login. Password is checked BEFORE revealing verification status.
    pub async fn login(&self, email: &str, password: &str) -> Result<TokenPair, AuthError> {
        let auth_service = &self.inner;

        let found = auth_service
            .store
            .find_by_email(&Self::normalize_email(email))
            .await
            .map_err(AuthError::Store)?;

        // always run exactly one Argon2 verify, even for unknown emails
        let hash = found
            .as_ref()
            .map(|u| u.password_hash().to_owned())
            .unwrap_or_else(|| auth_service.dummy_hash.clone());
        let ok = self.verify_password(password.to_owned(), hash).await?;

        let user = found.filter(|_| ok).ok_or(AuthError::InvalidCredentials)?;

        if !user.is_email_verified() {
            return Err(AuthError::EmailNotVerified);
        }

        auth_service
            .tokens
            .generate(&user.id())
            .await
            .map_err(AuthError::Token)
    }

    /// Current user data. The token is always validated; only user data is cached.
    pub async fn me(&self, access_token: &str) -> Result<Me, AuthError> {
        let claims = self.is_token_valid(access_token).await?;
        let auth_service = &self.inner;

        if let Some(cache) = &auth_service.cache {
            match cache.get(&claims.sub).await {
                Ok(Some(json)) => match serde_json::from_str::<Me>(&json) {
                    Ok(me) => {
                        metrics::counter!(M_CACHE_HITS).increment(1);
                        return Ok(me);
                    }
                    // unreadable entry: treat as a miss and overwrite it below
                    Err(e) => warn!(error = ?e, "cached user entry unreadable"),
                },
                Ok(None) => {
                    metrics::counter!(M_CACHE_MISSES).increment(1);
                }
                Err(e) => {
                    metrics::counter!(M_CACHE_READ_FAIL).increment(1);
                    warn!(error = ?e, "user cache read failed, using store");
                }
            }
        }

        let user = auth_service
            .store
            .find_by_id(&claims.sub)
            .await
            .map_err(AuthError::Store)?
            .ok_or(AuthError::NotFound)?;

        let me = Me::new(
            user.id(),
            user.email().to_owned(),
            user.is_email_verified(),
            user.extra(),
        );

        if let Some(cache) = &auth_service.cache {
            match serde_json::to_string(&me) {
                Ok(json) => {
                    if let Err(e) = cache.set(&claims.sub, &json, None).await {
                        metrics::counter!(M_CACHE_WRITE_FAIL).increment(1);
                        warn!(error = ?e, "user cache write failed");
                    }
                }
                Err(e) => error!(error = ?e, "could not serialize Me"),
            }
        }

        Ok(me)
    }

    /// Rotate: verify refresh token -> blacklist it -> issue a new pair.
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenPair, AuthError> {
        let auth_service = &self.inner;
        let claims = self.check(refresh_token, TokenType::Refresh).await?;

        let newly_revoked = auth_service
            .blacklist
            .blacklist_token(claims.jti(), claims.exp())
            .await
            .map_err(AuthError::Blacklist)?;
        if !newly_revoked {
            return Err(AuthError::BlacklistedToken);
        }

        let pair = auth_service
            .tokens
            .generate(&claims.sub)
            .await
            .map_err(AuthError::Token)?;

        // close the millisecond window: was the user revoked while we were generating?
        if let Some(cutoff) = auth_service
            .blacklist
            .sessions_revoked_before(&claims.sub)
            .await
            .map_err(AuthError::Blacklist)?
            && claims.iat <= cutoff
        {
            return Err(AuthError::InvalidToken);
        }

        Ok(pair)
    }

    /// Verify an email address.
    ///
    /// The token is claimed atomically with `take` (read + delete in one step),
    /// so two simultaneous requests can't both use it. If a transient failure
    /// happens after the claim, the token is put back so the user can retry.
    pub async fn verify_email(&self, token: &str) -> Result<(), AuthError> {
        let auth_service = &self.inner;
        let key = Self::ott_key(VERIFY, token);

        let user_id = auth_service
            .ott_store
            .take(&key)
            .await
            .map_err(AuthError::Ott)?
            .ok_or(AuthError::InvalidToken)?;

        let result: Result<(), AuthError> = async {
            let mut user = auth_service
                .store
                .find_by_id(&user_id)
                .await
                .map_err(AuthError::Store)?
                .ok_or(AuthError::NotFound)?;

            if user.is_email_verified() {
                return Err(AuthError::EmailAlreadyVerified);
            }

            user.set_email_verified(true);
            auth_service
                .store
                .update_user(user)
                .await
                .map_err(AuthError::Store)?;
            Ok(())
        }
        .await;

        if let Err(e) = &result {
            // Permanent outcomes: the token is correctly spent.
            // Anything else is transient: give the token back.
            if !matches!(e, AuthError::EmailAlreadyVerified | AuthError::NotFound)
                && let Err(restore_err) =
                    auth_service.ott_store.set(&key, &user_id, VERIFY_TTL).await
            {
                error!(user_id = %user_id, error = ?restore_err,
                           "Failed to restore verification token after error");
            }

            return result;
        }

        if let Err(e) = self.invalidate_user_cache(&user_id).await {
            warn!(user_id = %user_id, error = ?e, "cache invalidate failed; entry expires with its TTL");
        }

        Ok(())
    }

    /// Returns `Ok(())` for unknown emails so the endpoint can't be used to
    /// discover which emails are registered.
    pub async fn request_password_reset(&self, email: &str) -> Result<(), AuthError> {
        let auth_service = &self.inner;

        let Some(user) = auth_service
            .store
            .find_by_email(&Self::normalize_email(email))
            .await
            .map_err(AuthError::Store)?
        else {
            return Ok(());
        };

        let token = Uuid::new_v4().to_string();
        auth_service
            .ott_store
            .set(&Self::ott_key(RESET, &token), &user.id(), RESET_TTL)
            .await
            .map_err(AuthError::Ott)?;

        let subject = auth_service
            .email_templates
            .reset_password_subject(user.as_ref());
        let body = auth_service
            .email_templates
            .reset_password_body(user.as_ref(), &token);

        info!(user_id = %user.id(), "Sending password reset email");

        // logged, not returned: an error only for real accounts would leak existence
        if let Err(err) = auth_service
            .email_sender
            .send_email(user.email(), &subject, &body)
            .await
        {
            error!(user_id = %user.id(), error = ?err, "Failed to send password reset email");
        }
        Ok(())
    }

    pub async fn reset_password(&self, token: &str, new_password: &str) -> Result<(), AuthError> {
        let new_password = Self::check_password_length(new_password)?;
        let auth_service = &self.inner;
        let key = Self::ott_key(RESET, token);

        // Atomic read + delete. Of two simultaneous requests, only one gets Some(..).
        let user_id = auth_service
            .ott_store
            .take(&key)
            .await
            .map_err(AuthError::Ott)?
            .ok_or(AuthError::InvalidToken)?;

        let mut user = auth_service
            .store
            .find_by_id(&user_id)
            .await
            .map_err(AuthError::Store)?
            .ok_or(AuthError::NotFound)?;

        let hash = self.hash_password(new_password.to_owned()).await?;
        user.set_password_hash(hash);
        auth_service
            .store
            .update_user(user)
            .await
            .map_err(AuthError::Store)?;

        // Void every session issued before this moment.
        auth_service
            .blacklist
            .revoke_user_sessions(
                &user_id,
                Self::now_unix_secs(),
                auth_service.tokens.refresh_ttl_secs(),
            )
            .await
            .map_err(AuthError::Blacklist)?;

        if let Err(e) = self.invalidate_user_cache(&user_id).await {
            warn!(user_id = %user_id, error = ?e, "cache invalidate failed; entry expires with its TTL");
        }

        Ok(())
    }

    /// Change password for a logged-in user who knows the current one.
    ///
    /// `user_id` MUST come from a validated access token (`is_token_valid`),
    /// never from request input. All sessions are revoked afterwards, including
    /// the caller's own, so the client has to log in again with the new password.
    pub async fn change_password(
        &self,
        user_id: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), AuthError> {
        let new_password = Self::check_password_length(new_password)?;
        let auth_service = &self.inner;

        let mut user = auth_service
            .store
            .find_by_id(user_id)
            .await
            .map_err(AuthError::Store)?
            .ok_or(AuthError::NotFound)?;

        let ok = self
            .verify_password(old_password.to_owned(), user.password_hash().to_owned())
            .await?;
        if !ok {
            return Err(AuthError::InvalidCredentials);
        }

        let hash = self.hash_password(new_password.to_owned()).await?;
        user.set_password_hash(hash);
        auth_service
            .store
            .update_user(user)
            .await
            .map_err(AuthError::Store)?;

        // Void every session issued before this moment.
        auth_service
            .blacklist
            .revoke_user_sessions(
                user_id,
                Self::now_unix_secs(),
                auth_service.tokens.refresh_ttl_secs(),
            )
            .await
            .map_err(AuthError::Blacklist)?;

        if let Err(e) = self.invalidate_user_cache(user_id).await {
            warn!(user_id = %user_id, error = ?e, "cache invalidate failed; entry expires with its TTL");
        }

        Ok(())
    }

    /// Permanently delete the account after re-checking the password.
    ///
    /// `user_id` MUST come from a validated access token. Sessions are revoked
    /// BEFORE the delete: if the delete then fails the user is just logged out
    /// and can retry, whereas the other order could leave live tokens for an
    /// account that no longer exists.
    pub async fn delete_account(&self, user_id: &str, password: &str) -> Result<(), AuthError> {
        let auth_service = &self.inner;

        let user = auth_service
            .store
            .find_by_id(user_id)
            .await
            .map_err(AuthError::Store)?
            .ok_or(AuthError::NotFound)?;

        let ok = self
            .verify_password(password.to_owned(), user.password_hash().to_owned())
            .await?;
        if !ok {
            return Err(AuthError::InvalidCredentials);
        }

        auth_service
            .blacklist
            .revoke_user_sessions(
                user_id,
                Self::now_unix_secs(),
                auth_service.tokens.refresh_ttl_secs(),
            )
            .await
            .map_err(AuthError::Blacklist)?;

        auth_service
            .store
            .delete_user(user_id)
            .await
            .map_err(AuthError::Store)?;

        if let Err(e) = self.invalidate_user_cache(user_id).await {
            warn!(user_id = %user_id, error = ?e, "cache invalidate failed; entry expires with its TTL");
        }

        info!(user_id = %user_id, "Account deleted");
        Ok(())
    }

    /// Log the user out of every device by voiding all sessions issued so far.
    ///
    /// `user_id` MUST come from a validated access token. Tokens issued after
    /// this call (a fresh login) work normally.
    pub async fn logout_all(&self, user_id: &str) -> Result<(), AuthError> {
        let auth_service = &self.inner;
        auth_service
            .blacklist
            .revoke_user_sessions(
                user_id,
                Self::now_unix_secs(),
                auth_service.tokens.refresh_ttl_secs(),
            )
            .await
            .map_err(AuthError::Blacklist)
    }

    /// Logout by blacklisting the refresh token (idempotent).
    pub async fn logout(&self, refresh_token: &str) -> Result<(), AuthError> {
        let auth_service = &self.inner;
        let claims = auth_service
            .tokens
            .verify(refresh_token)
            .await
            .map_err(|_| AuthError::InvalidToken)?;
        if claims.typ != TokenType::Refresh {
            return Err(AuthError::InvalidToken);
        }
        auth_service
            .blacklist
            .blacklist_token(claims.jti(), claims.exp())
            .await
            .map_err(AuthError::Blacklist)?;
        Ok(())
    }

    /// Use in auth middleware / extractors. Only ACCESS tokens pass.
    pub async fn is_token_valid(&self, token: &str) -> Result<Claims, AuthError> {
        self.check(token, TokenType::Access).await
    }
}
