use crate::configs::AuthServiceBuilder;
use crate::traits::*;
use tracing::{error, info};
use uuid::Uuid;

#[derive(Debug)]
pub enum AuthError<S, T, B, E, O> {
    Store(S),
    Token(T),
    Blacklist(B),
    Email(E),
    Ott(O),

    BlacklistedToken,
    EmailAlreadyExists,
    NotFound,
    InvalidToken,
    EmailAlreadyVerified,
}

#[derive(Debug)]
pub enum LoginError<T, S> {
    InvalidCredentials,
    EmailNotVerified,
    Store(S),
    Token(T),
}

#[derive(Debug, Clone)]
pub struct AuthService<S, P, T, B, E, M, V> {
    pub store: S,
    pub hasher: P,
    pub tokens: T,
    pub blacklist: B,
    pub email_sender: E,
    pub email_templates: M,
    pub ott_store: V,
}

impl<S, P, T, B, E, M, V> AuthService<S, P, T, B, E, M, V> {
    pub fn builder() -> AuthServiceBuilder<S, P, T, B, E, M, V> {
        AuthServiceBuilder::new()
    }

    /// Register a new user account
    pub async fn register(
        &mut self,
        input: S::RegisterDto,
    ) -> Result<S::User, AuthError<S::Error, T::Error, B::Error, E::Error, V::Error>>
    where
        S: UserStore,
        P: PasswordHasher,
        T: TokenManager,
        B: TokenBlacklistStore,
        E: EmailProvider,
        M: EmailTemplateConfig<S::User>,
        V: OneTimeTokenStore,
    {
        // Ensure email is unique
        if self.store.find_by_email(input.email()).await.is_some() {
            return Err(AuthError::EmailAlreadyExists);
        }

        // Hash password
        let hash = self.hasher.hash(input.password());

        // Create user
        let user = self
            .store
            .create_user(input, hash)
            .await
            .map_err(AuthError::Store)?;

        // Create verification token
        let token = Uuid::new_v4().to_string();

        // Store verification token
        if let Err(err) = self.ott_store.set(&token, &user.id(), 60 * 60 * 24).await {
            if let Err(delete_err) = self.store.delete_user(&user.id()).await {
                error!(
                    user_id = %user.id(),
                    error = ?delete_err,
                    "Failed to roll back user after token creation failure"
                );
            }

            return Err(AuthError::Ott(err));
        }

        // Build email
        let subject = self.email_templates.verify_email_subject(&user);
        let body = self.email_templates.verify_email_body(&user, &token);

        info!(
            user_id = %user.id(),
            email = %user.email(),
            "Sending verification email"
        );

        // Send verification email
        if let Err(err) = self
            .email_sender
            .send_email(user.email(), &subject, &body)
            .await
        {
            error!(
                user_id = %user.id(),
                email = %user.email(),
                error = ?err,
                "Failed to send verification email"
            );

            // Remove verification token
            if let Err(delete_err) = self.ott_store.delete(&token).await {
                error!(
                    token = %token,
                    error = ?delete_err,
                    "Failed to roll back verification token"
                );
            }

            // Remove created user
            if let Err(delete_err) = self.store.delete_user(&user.id()).await {
                error!(
                    user_id = %user.id(),
                    error = ?delete_err,
                    "Failed to roll back created user"
                );
            }

            return Err(AuthError::Email(err));
        }

        info!(
            user_id = %user.id(),
            email = %user.email(),
            "Verification email sent successfully"
        );

        Ok(user)
    }

    /// Login
    pub async fn login(
        &self,
        email: &str,
        password: &str,
    ) -> Result<T::Token, LoginError<T::Error, S::Error>>
    where
        S: UserStore,
        P: PasswordHasher,
        T: TokenManager,
    {
        let user = self
            .store
            .find_by_email(email)
            .await
            .ok_or(LoginError::InvalidCredentials)?;

        let verified = self
            .store
            .check_email_verified(&user.id())
            .await
            .map_err(LoginError::Store)?;

        if !verified {
            return Err(LoginError::EmailNotVerified);
        }

        if !self.hasher.verify(password, user.password_hash()) {
            return Err(LoginError::InvalidCredentials);
        }

        self.tokens
            .generate(&user.id())
            .await
            .map_err(LoginError::Token)
    }

    /// Refresh token
    pub async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<T::Token, AuthError<(), T::Error, B::Error, (), V::Error>>
    where
        T: TokenManager,
        T::Claims: BlacklistableClaims,
        B: TokenBlacklistStore,
        V: OneTimeTokenStore,
    {
        let claims = self
            .tokens
            .verify(refresh_token)
            .await
            .map_err(AuthError::Token)?;

        let blacklisted = self
            .blacklist
            .is_blacklisted(claims.jti())
            .await
            .map_err(AuthError::Blacklist)?;

        if blacklisted {
            return Err(AuthError::BlacklistedToken);
        }

        self.blacklist
            .blacklist_token(claims.jti(), claims.exp())
            .await
            .map_err(AuthError::Blacklist)?;

        self.tokens
            .refresh(refresh_token)
            .await
            .map_err(AuthError::Token)
    }

    /// Verify email
    pub async fn verify_email(
        &self,
        token: &str,
    ) -> Result<(), AuthError<S::Error, (), (), (), V::Error>>
    where
        S: UserStore,
        V: OneTimeTokenStore,
    {
        let user_id = self
            .ott_store
            .get(token)
            .await
            .map_err(AuthError::Ott)?
            .ok_or(AuthError::InvalidToken)?;

        let mut user = self
            .store
            .find_by_id(&user_id)
            .await
            .ok_or(AuthError::NotFound)?;

        let is_verified = self
            .store
            .check_email_verified(&user_id)
            .await
            .map_err(AuthError::Store)?;

        if is_verified {
            return Err(AuthError::EmailAlreadyVerified);
        }

        user.set_email_verified(true);

        self.store
            .update_user(user)
            .await
            .map_err(AuthError::Store)?;

        self.ott_store.delete(token).await.map_err(AuthError::Ott)?;

        Ok(())
    }

    /// Request password reset
    pub async fn request_password_reset(
        &self,
        email: &str,
    ) -> Result<(), AuthError<S::Error, (), (), E::Error, V::Error>>
    where
        S: UserStore,
        V: OneTimeTokenStore,
        M: EmailTemplateConfig<S::User>,
        E: EmailProvider,
    {
        let user = self
            .store
            .find_by_email(email)
            .await
            .ok_or(AuthError::NotFound)?;

        let token = Uuid::new_v4().to_string();

        self.ott_store
            .set(&token, &user.id(), 60 * 15)
            .await
            .map_err(AuthError::Ott)?;

        let subject = self.email_templates.reset_password_subject(&user);
        let body = self.email_templates.reset_password_body(&user, &token);

        info!(
            user_id = %user.id(),
            email = %user.email(),
            "Sending password reset email"
        );

        self.email_sender
            .send_email(user.email(), &subject, &body)
            .await
            .map_err(|err| {
                error!(
                    user_id = %user.id(),
                    email = %user.email(),
                    error = ?err,
                    "Failed to send password reset email"
                );

                AuthError::Email(err)
            })?;

        info!(
            user_id = %user.id(),
            email = %user.email(),
            "Password reset email sent successfully"
        );

        Ok(())
    }

    /// Reset password
    pub async fn reset_password(
        &self,
        token: &str,
        new_password: &str,
    ) -> Result<(), AuthError<S::Error, (), (), (), V::Error>>
    where
        S: UserStore,
        P: PasswordHasher,
        V: OneTimeTokenStore,
    {
        let user_id = self
            .ott_store
            .get(token)
            .await
            .map_err(AuthError::Ott)?
            .ok_or(AuthError::InvalidToken)?;

        let mut user = self
            .store
            .find_by_id(&user_id)
            .await
            .ok_or(AuthError::NotFound)?;

        let password_hash = self.hasher.hash(new_password);
        user.set_password_hash(password_hash);

        self.store
            .update_user(user)
            .await
            .map_err(AuthError::Store)?;

        self.ott_store.delete(token).await.map_err(AuthError::Ott)?;

        Ok(())
    }

    /// Logout by blacklisting the refresh token
    pub async fn logout(
        &self,
        refresh_token: &str,
    ) -> Result<(), AuthError<(), T::Error, B::Error, (), ()>>
    where
        T: TokenManager,
        T::Claims: BlacklistableClaims,
        B: TokenBlacklistStore,
    {
        // Verify the refresh token to extract claims (like JTI and exp)
        let claims = self
            .tokens
            .verify(refresh_token)
            .await
            .map_err(AuthError::Token)?;

        // Blacklist this token until it naturally expires
        self.blacklist
            .blacklist_token(claims.jti(), claims.exp())
            .await
            .map_err(AuthError::Blacklist)?;

        Ok(())
    }

    /// Check token
    pub async fn is_token_valid(
        &self,
        token: &str,
    ) -> Result<T::Claims, AuthError<(), T::Error, B::Error, (), V::Error>>
    where
        T: TokenManager,
        T::Claims: BlacklistableClaims,
        B: TokenBlacklistStore,
        V: OneTimeTokenStore,
    {
        let claims = self.tokens.verify(token).await.map_err(AuthError::Token)?;

        let blacklisted = self
            .blacklist
            .is_blacklisted(claims.jti())
            .await
            .map_err(AuthError::Blacklist)?;

        if blacklisted {
            return Err(AuthError::BlacklistedToken);
        }

        Ok(claims)
    }
}
