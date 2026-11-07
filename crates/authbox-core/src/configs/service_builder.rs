use crate::errors::BuildError;
use crate::services::AuthService;
use crate::traits::*;

#[derive(Default)]
pub struct AuthServiceBuilder {
    store: Option<Box<dyn UserStore>>,
    hasher: Option<Box<dyn PasswordHasher>>,
    tokens: Option<Box<dyn TokenManager>>,
    blacklist: Option<Box<dyn TokenBlacklistStore>>,
    email_sender: Option<Box<dyn EmailProvider>>,
    email_templates: Option<Box<dyn EmailTemplateConfig>>,
    ott_store: Option<Box<dyn OneTimeTokenStore>>,
    cache: Option<Box<dyn UserCache>>,
}

impl AuthServiceBuilder {
    // same method names as v2, so existing chains keep compiling
    pub fn store(mut self, v: impl UserStore + 'static) -> Self {
        self.store = Some(Box::new(v));
        self
    }
    pub fn hasher(mut self, v: impl PasswordHasher + 'static) -> Self {
        self.hasher = Some(Box::new(v));
        self
    }
    pub fn tokens(mut self, v: impl TokenManager + 'static) -> Self {
        self.tokens = Some(Box::new(v));
        self
    }
    pub fn blacklist(mut self, v: impl TokenBlacklistStore + 'static) -> Self {
        self.blacklist = Some(Box::new(v));
        self
    }
    pub fn email_sender(mut self, v: impl EmailProvider + 'static) -> Self {
        self.email_sender = Some(Box::new(v));
        self
    }
    pub fn email_templates(mut self, v: impl EmailTemplateConfig + 'static) -> Self {
        self.email_templates = Some(Box::new(v));
        self
    }
    pub fn ott_store(mut self, v: impl OneTimeTokenStore + 'static) -> Self {
        self.ott_store = Some(Box::new(v));
        self
    }

    /// Optional. Without it, `me()` reads the user store on every call.
    /// For a ready-made in-memory cache, see the `authbox-defaults` crate.
    pub fn user_cache(mut self, v: impl UserCache + 'static) -> Self {
        self.cache = Some(Box::new(v));
        self
    }

    pub fn build(self) -> Result<AuthService, BuildError> {
        Ok(AuthService::new(
            self.store.ok_or(BuildError::Missing("store"))?,
            self.hasher.ok_or(BuildError::Missing("hasher"))?,
            self.tokens.ok_or(BuildError::Missing("tokens"))?,
            self.blacklist.ok_or(BuildError::Missing("blacklist"))?,
            self.email_sender
                .ok_or(BuildError::Missing("email_sender"))?,
            self.email_templates
                .ok_or(BuildError::Missing("email_templates"))?,
            self.ott_store.ok_or(BuildError::Missing("ott_store"))?,
            self.cache,
        ))
    }
}
