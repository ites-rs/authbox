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

// Everything the service needs to do its job. Wrapped in an Arc so AuthService
// is cheap to clone (e.g. for passing into axum handlers).
pub(crate) struct Inner {
    pub(crate) store: Box<dyn UserStore>,
    pub(crate) hasher: Box<dyn PasswordHasher>,
    pub(crate) tokens: Box<dyn TokenManager>,
    pub(crate) blacklist: Box<dyn TokenBlacklistStore>,
    pub(crate) email_sender: Box<dyn EmailProvider>,
    pub(crate) email_templates: Box<dyn EmailTemplateConfig>,
    pub(crate) ott_store: Box<dyn OneTimeTokenStore>,
    pub(crate) cache: Option<Box<dyn UserCache>>,
    /// A bcrypt/argon2 hash of a random UUID we generate at startup. We verify
    /// against this for emails that don't exist in the DB so an attacker can't
    /// tell valid from invalid accounts by measuring response time.
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

    // Argon2 is intentionally slow, so we shove it onto a blocking thread to
    // avoid stalling the async runtime.
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

    /// Full token validation in one place: signature, expiry, correct type,
    /// blacklist check, and the session-revocation cutoff. Called by both
    /// `is_token_valid` (access) and `refresh_token` (refresh) so the logic
    /// doesn't drift between the two paths.
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

        // If someone called logout_all or change_password, every token issued
        // before that moment is dead even if it isn't individually blacklisted.
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

    /// Best-effort cleanup when registration fails partway through. We log
    /// errors but don't surface them — the caller already has an error to
    /// return and there's nothing the user can do about a cleanup failure.
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

    /// 12–128 chars. 12 is tight but anything shorter is genuinely dangerous.
    /// 128 is a DoS guard — hashing a 1 MB password is expensive on purpose.
    fn check_password_length(password: &str) -> Result<&str, AuthError> {
        let n = password.chars().count();
        if (12..=128).contains(&n) {
            Ok(password)
        } else {
            Err(AuthError::password_length())
        }
    }

    // Trim whitespace and lowercase so "User@Example.COM " and "user@example.com"
    // are always treated as the same address.
    fn normalize_email(email: &str) -> String {
        email.trim().to_lowercase()
    }

    /// Namespacing OTT keys by purpose stops a verify token from being
    /// redeemed as a reset token and vice versa.
    fn ott_key(purpose: &str, token: &str) -> String {
        format!("{purpose}:{token}")
    }

    // Unix seconds, same unit JWT uses for `iat`/`exp`. We only need second
    // granularity here so the cast from u64 to i64 is fine until year 2038+.
    fn now_unix_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before 1970")
            .as_secs() as i64
    }

    /// Tries to pull an `EmailAlreadyExists` back out of the opaque store
    /// error so we can return the right variant to the caller. If you're using
    /// sqlx + Postgres, this is where you'd check `is_unique_violation()`.
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
    fn map_store_create_err(e: crate::errors::BoxError) -> AuthError {
        if let Some(AuthError::EmailAlreadyExists) = e.downcast_ref::<AuthError>() {
            return AuthError::EmailAlreadyExists;
        }
        AuthError::Store(e)
    }

    /// Mints a one-time token, writes it to the OTT store, then fires the
    /// verification email. If the OTT write fails we bail immediately —
    /// nothing to clean up yet. If the email send fails we delete the token
    /// so it doesn't sit there orphaned.
    ///
    /// We deliberately don't touch the user record here. Whether to roll the
    /// account back on failure is the caller's call — `register` does it
    /// because the account was just created, `request_verify_email` doesn't
    /// because the account already existed before we got here.
    async fn send_verification_email(&self, user: &dyn AuthUser) -> Result<(), AuthError> {
        let auth_service = &self.inner;
        let user_id = user.id();

        let token = Uuid::new_v4().to_string();
        let key = Self::ott_key(VERIFY, &token);

        auth_service
            .ott_store
            .set(&key, &user_id, VERIFY_TTL)
            .await
            .map_err(AuthError::Ott)?;

        let subject = auth_service.email_templates.verify_email_subject(user);
        let body = auth_service.email_templates.verify_email_body(user, &token);

        info!(user_id = %user_id, "Sending verification email");

        if let Err(err) = auth_service
            .email_sender
            .send_email(user.email(), &subject, &body)
            .await
        {
            error!(user_id = %user_id, error = ?err, "Failed to send verification email");

            if let Err(e) = auth_service.ott_store.delete(&key).await {
                error!(error = ?e, "Failed to roll back verification token");
            }
            return Err(AuthError::Email(err));
        }

        info!(user_id = %user_id, "Verification email sent successfully");
        Ok(())
    }

    /// Same idea as `send_verification_email` but for password reset. One
    /// difference: email send failures are logged and swallowed rather than
    /// returned. If we returned an error only for real accounts an attacker
    /// could use this endpoint to enumerate registered addresses.
    async fn send_password_reset_email(&self, user: &dyn AuthUser) -> Result<(), AuthError> {
        let auth_service = &self.inner;
        let user_id = user.id();

        let token = Uuid::new_v4().to_string();
        auth_service
            .ott_store
            .set(&Self::ott_key(RESET, &token), &user_id, RESET_TTL)
            .await
            .map_err(AuthError::Ott)?;

        let subject = auth_service.email_templates.reset_password_subject(user);
        let body = auth_service
            .email_templates
            .reset_password_body(user, &token);

        info!(user_id = %user_id, "Sending password reset email");

        if let Err(err) = auth_service
            .email_sender
            .send_email(user.email(), &subject, &body)
            .await
        {
            error!(user_id = %user_id, error = ?err, "Failed to send password reset email");
        }

        Ok(())
    }

    /// Creates a new account and sends a verification email. Fails fast if the
    /// password is too short/long or if the email is already taken.
    ///
    /// The `find_by_email` pre-check is a fast path only — it doesn't protect
    /// against two requests racing in at the same millisecond. Your DB needs a
    /// UNIQUE constraint on the email column, and `create_user` must map that
    /// violation to `AuthError::EmailAlreadyExists`. See `map_store_create_err`.
    ///
    /// If anything after `create_user` fails (OTT write, email send) we delete
    /// the new record so the user can try again with the same address.
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

        if let Err(err) = self.send_verification_email(user.as_ref()).await {
            self.rollback_user(&user_id).await;
            return Err(err);
        }

        Ok(user)
    }

    /// Re-sends a verification email. Returns `Ok(())` for unknown addresses
    /// and already-verified accounts so callers can't use this to fish for
    /// registered emails.
    pub async fn request_verify_email(&self, email: &str) -> Result<(), AuthError> {
        let auth_service = &self.inner;

        let user = match auth_service
            .store
            .find_by_email(&Self::normalize_email(email))
            .await
            .map_err(AuthError::Store)?
        {
            Some(u) => u,
            None => return Ok(()),
        };

        if user.is_email_verified() {
            return Ok(());
        }

        self.send_verification_email(user.as_ref()).await
    }

    /// Checks the password before saying anything about verification status —
    /// we don't want to tell someone "that email isn't verified" unless they
    /// actually know the password. We also always run exactly one Argon2 verify
    /// even for unknown emails so response time doesn't betray whether an
    /// address is registered.
    pub async fn login(&self, email: &str, password: &str) -> Result<TokenPair, AuthError> {
        let auth_service = &self.inner;

        let found = auth_service
            .store
            .find_by_email(&Self::normalize_email(email))
            .await
            .map_err(AuthError::Store)?;

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

    /// Returns the current user's profile. The token is always fully validated;
    /// only the user record itself is cached. Cache misses and read errors fall
    /// through to the store transparently.
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
                    // Corrupt/stale entry ,  treat it as a miss and overwrite below.
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

    /// Validates the refresh token, blacklists it, then issues a fresh pair.
    /// We check `newly_revoked` to catch replay attacks — if the same token
    /// comes in twice, the second one loses because the first already claimed it.
    ///
    /// There's a small window between issuing the new pair and the second
    /// revocation check. The extra check at the end closes it: if the user
    /// was globally logged out in that gap, we catch it and return an error
    /// instead of handing out tokens for a revoked session.
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

    /// Redeems a one-time email verification token. The token is claimed with
    /// `take` (atomic read + delete) so two simultaneous requests can't both
    /// succeed. If anything goes wrong after the claim we try to put the token
    /// back so the user can retry — except for `EmailAlreadyVerified` and
    /// `NotFound` which are permanent outcomes where restoring the token would
    /// just confuse things.
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

    /// Kicks off a password reset. Always returns `Ok(())` — we don't tell
    /// the caller whether the email was found or not, and we don't surface email
    /// send errors, both for the same reason: doing so would let an attacker
    /// check whether a given address is registered.
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

        self.send_password_reset_email(user.as_ref()).await
    }

    /// Redeems a password-reset token and updates the hash. After a successful
    /// reset every existing session is voided — the user has to log in again
    /// with the new password, which is the right UX (and prevents someone who
    /// stole a session from staying logged in after a password change).
    pub async fn reset_password(&self, token: &str, new_password: &str) -> Result<(), AuthError> {
        let new_password = Self::check_password_length(new_password)?;
        let auth_service = &self.inner;
        let key = Self::ott_key(RESET, token);

        // Atomic read + delete so two parallel requests can't both succeed.
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

    /// Lets a logged-in user change their own password. `user_id` must come
    /// from a validated access token — never trust this from request input.
    /// We re-verify the old password first so a stolen session token alone
    /// isn't enough to take over the account. All sessions are revoked after,
    /// including this one, so the client needs to re-authenticate.
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

    /// Hard-deletes the account after re-checking the password. `user_id` must
    /// come from a validated access token.
    ///
    /// We revoke sessions first, then delete. The order matters: if we deleted
    /// first and then the revocation failed, we'd have a window where tokens
    /// are still valid for an account that no longer exists. The other way
    /// around, a failed delete just leaves the user logged out — annoying but
    /// recoverable.
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

    /// Logs the user out of every device at once by stamping a revocation
    /// cutoff. Any token issued before this moment is now dead. Tokens issued
    /// after a fresh login work normally. `user_id` must come from a validated
    /// access token.
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

    /// Single-device logout — blacklists just this refresh token. Idempotent;
    /// blacklisting an already-blacklisted token is fine. We don't validate
    /// the token's blacklist or cutoff status here on purpose: even an already-
    /// invalid token should be blacklisted so it can't sneak through if the
    /// blacklist was temporarily down when the user first tried to log out.
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

    /// What you call in middleware / extractors to gate a route. Only access
    /// tokens pass — refresh tokens are rejected even if they're otherwise
    /// valid. Returns the full claims so handlers can get the user ID without
    /// making a second round-trip.
    pub async fn is_token_valid(&self, token: &str) -> Result<Claims, AuthError> {
        self.check(token, TokenType::Access).await
    }
}
