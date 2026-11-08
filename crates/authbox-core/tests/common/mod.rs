// in-memory versions of all the authbox traits + a Harness that wires them
// into an AuthService.
//
// everything here is Clone and shares state through an Arc, so a test can give
// one copy to the builder and keep another to look at afterwards.
#![allow(dead_code)]

use async_trait::async_trait;
use authbox_core::prelude::*;
use authbox_core::services::AuthService;
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const PW: &str = "correct-horse-battery"; // 21 chars
pub const PW2: &str = "a-brand-new-password-1"; // 22 chars

// clock

// real time + an offset the test controls, so we can "wait" without sleeping.
// the service itself uses the real clock for the revoke cutoff, so a token
// made after advance(n) has an iat bigger than any earlier cutoff
#[derive(Clone, Default)]
pub struct Clock(Arc<AtomicI64>);

impl Clock {
    pub fn now(&self) -> i64 {
        let real = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        real + self.0.load(SeqCst)
    }

    pub fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, SeqCst);
    }
}

// hasher

pub struct FakeHasher;

impl PasswordHasher for FakeHasher {
    fn hash(&self, password: &str) -> String {
        format!("hashed:{password}")
    }

    fn verify(&self, password: &str, hash: &str) -> bool {
        hash == format!("hashed:{password}")
    }
}

// tokens

// tokens look like access|sub|jti-3|iat|exp
// not secure at all, just easy to parse
#[derive(Clone)]
pub struct TestTokens {
    clock: Clock,
    access_ttl: i64,
    refresh_ttl: i64,
    counter: Arc<AtomicUsize>,
}

impl TestTokens {
    pub fn new(clock: Clock, access_ttl: i64, refresh_ttl: i64) -> Self {
        Self {
            clock,
            access_ttl,
            refresh_ttl,
            counter: Arc::default(),
        }
    }

    fn make(&self, sub: &str, typ: TokenType) -> String {
        let now = self.clock.now();
        let (name, ttl) = match typ {
            TokenType::Access => ("access", self.access_ttl),
            TokenType::Refresh => ("refresh", self.refresh_ttl),
        };
        let n = self.counter.fetch_add(1, SeqCst);
        format!("{name}|{sub}|jti-{n}|{now}|{}", now + ttl)
    }
}

#[async_trait]
impl TokenManager for TestTokens {
    async fn generate(&self, user_id: &str) -> Result<TokenPair, BoxError> {
        Ok(TokenPair {
            access_token: self.make(user_id, TokenType::Access),
            refresh_token: self.make(user_id, TokenType::Refresh),
            expires_in: self.access_ttl as usize,
            token_type: "Bearer".into(),
        })
    }

    async fn verify(&self, token: &str) -> Result<Claims, BoxError> {
        let p: Vec<&str> = token.split('|').collect();
        if p.len() != 5 {
            return Err("malformed token".into());
        }
        let typ = match p[0] {
            "access" => TokenType::Access,
            "refresh" => TokenType::Refresh,
            _ => return Err("unknown token type".into()),
        };
        let iat: i64 = p[3].parse()?;
        let exp: i64 = p[4].parse()?;
        if exp <= self.clock.now() {
            return Err("expired".into());
        }
        Ok(Claims {
            sub: p[1].to_owned(),
            jti: p[2].to_owned(),
            exp,
            iat,
            typ,
        })
    }

    fn refresh_ttl_secs(&self) -> u64 {
        self.refresh_ttl as u64
    }
}

// blacklist

#[derive(Clone, Default)]
pub struct MemBlacklist {
    jtis: Arc<Mutex<HashSet<String>>>,
    revoked: Arc<Mutex<HashMap<String, i64>>>,
    gate: Arc<Mutex<Option<Arc<tokio::sync::Barrier>>>>,
}

impl MemBlacklist {
    // makes is_blacklisted wait until n callers are in it. that way n parallel
    // requests all pass the "not blacklisted" check before any of them
    // blacklists the token, which is the race we want to hit
    pub fn gate_is_blacklisted(&self, n: usize) {
        *self.gate.lock().unwrap() = Some(Arc::new(tokio::sync::Barrier::new(n)));
    }
}

#[async_trait]
impl TokenBlacklistStore for MemBlacklist {
    async fn is_blacklisted(&self, jti: &str) -> Result<bool, BoxError> {
        let seen = self.jtis.lock().unwrap().contains(jti);
        let gate = self.gate.lock().unwrap().clone();
        if let Some(barrier) = gate {
            barrier.wait().await;
        }
        Ok(seen)
    }

    // like redis SET NX, only the call that actually inserted gets true
    async fn blacklist_token(&self, jti: &str, _expires_at: i64) -> Result<bool, BoxError> {
        Ok(self.jtis.lock().unwrap().insert(jti.to_owned()))
    }

    async fn revoke_user_sessions(
        &self,
        user_id: &str,
        cutoff: i64,
        _ttl_seconds: u64,
    ) -> Result<(), BoxError> {
        self.revoked
            .lock()
            .unwrap()
            .insert(user_id.to_owned(), cutoff);
        Ok(())
    }

    async fn sessions_revoked_before(&self, user_id: &str) -> Result<Option<i64>, BoxError> {
        Ok(self.revoked.lock().unwrap().get(user_id).copied())
    }
}

// email

#[derive(Clone, Debug)]
pub struct Sent {
    pub to: String,
    pub subject: String,
    pub body: String,
}

#[derive(Clone, Default)]
pub struct MemMailer {
    sent: Arc<Mutex<Vec<Sent>>>,
    fail: Arc<AtomicBool>,
}

impl MemMailer {
    pub fn set_fail(&self, v: bool) {
        self.fail.store(v, SeqCst);
    }

    pub fn count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }

    pub fn last(&self) -> Option<Sent> {
        self.sent.lock().unwrap().last().cloned()
    }
}

#[async_trait]
impl EmailProvider for MemMailer {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), BoxError> {
        if self.fail.load(SeqCst) {
            return Err("smtp down".into());
        }
        self.sent.lock().unwrap().push(Sent {
            to: to.to_owned(),
            subject: subject.to_owned(),
            body: body.to_owned(),
        });
        Ok(())
    }
}

// the email body is just the token so tests can read it back easily
pub struct TestTemplates;

impl EmailTemplateConfig for TestTemplates {
    fn verify_email_subject(&self, _user: &dyn AuthUser) -> String {
        "verify".into()
    }

    fn verify_email_body(&self, _user: &dyn AuthUser, token: &str) -> String {
        token.to_owned()
    }

    fn reset_password_subject(&self, _user: &dyn AuthUser) -> String {
        "reset".into()
    }

    fn reset_password_body(&self, _user: &dyn AuthUser, token: &str) -> String {
        token.to_owned()
    }
}

// one-time tokens

#[derive(Clone, Default)]
pub struct MemOtt(Arc<Mutex<HashMap<String, String>>>);

impl MemOtt {
    pub fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

#[async_trait]
impl OneTimeTokenStore for MemOtt {
    async fn set(&self, key: &str, value: &str, _ttl_seconds: u64) -> Result<(), BoxError> {
        self.0
            .lock()
            .unwrap()
            .insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<String>, BoxError> {
        Ok(self.0.lock().unwrap().get(key).cloned())
    }

    async fn delete(&self, key: &str) -> Result<(), BoxError> {
        self.0.lock().unwrap().remove(key);
        Ok(())
    }

    // like redis GETDEL: remove and return under one lock so only one caller
    // gets Some. the mutex is never held across an await
    async fn take(&self, key: &str) -> Result<Option<String>, BoxError> {
        Ok(self.0.lock().unwrap().remove(key))
    }
}

// user cache

#[derive(Clone, Default)]
pub struct MemCache {
    map: Arc<Mutex<HashMap<String, String>>>,
    fail: Arc<AtomicBool>,
}

impl MemCache {
    // every call on this one returns an error
    pub fn failing() -> Self {
        let c = Self::default();
        c.set_fail(true);
        c
    }

    pub fn set_fail(&self, v: bool) {
        self.fail.store(v, SeqCst);
    }

    pub fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }
}

#[async_trait]
impl UserCache for MemCache {
    async fn get(&self, user_id: &str) -> Result<Option<String>, BoxError> {
        if self.fail.load(SeqCst) {
            return Err("cache down".into());
        }
        Ok(self.map.lock().unwrap().get(user_id).cloned())
    }

    async fn set(
        &self,
        user_id: &str,
        value: &str,
        _ttl_seconds: Option<u64>,
    ) -> Result<(), BoxError> {
        if self.fail.load(SeqCst) {
            return Err("cache down".into());
        }
        self.map
            .lock()
            .unwrap()
            .insert(user_id.to_owned(), value.to_owned());
        Ok(())
    }

    async fn invalidate(&self, user_id: &str) -> Result<(), BoxError> {
        if self.fail.load(SeqCst) {
            return Err("cache down".into());
        }
        self.map.lock().unwrap().remove(user_id);
        Ok(())
    }
}

// user + store

#[derive(Clone, Debug)]
pub struct TestUser {
    pub id: String,
    pub email: String,
    pub hash: String,
    pub verified: bool,
}

impl AuthUser for TestUser {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn email(&self) -> &str {
        &self.email
    }

    fn password_hash(&self) -> &str {
        &self.hash
    }

    fn is_email_verified(&self) -> bool {
        self.verified
    }

    fn set_email_verified(&mut self, verified: bool) {
        self.verified = verified;
    }

    fn set_password_hash(&mut self, hash: String) {
        self.hash = hash;
    }

    fn extra(&self) -> Option<serde_json::Value> {
        Some(serde_json::json!({ "role": "tester" }))
    }
}

pub struct TestRegister {
    pub email: String,
    pub password: String,
}

pub fn reg(email: &str, password: &str) -> TestRegister {
    TestRegister {
        email: email.to_owned(),
        password: password.to_owned(),
    }
}

impl RegisterUserInput for TestRegister {
    fn email(&self) -> &str {
        &self.email
    }

    fn password(&self) -> &str {
        &self.password
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Clone, Default)]
pub struct MemStore {
    users: Arc<Mutex<HashMap<String, TestUser>>>,
    next_id: Arc<AtomicUsize>,
    find_by_id_calls: Arc<AtomicUsize>,
}

impl MemStore {
    pub fn user_count(&self) -> usize {
        self.users.lock().unwrap().len()
    }

    pub fn find_by_id_calls(&self) -> usize {
        self.find_by_id_calls.load(SeqCst)
    }
}

fn boxed(u: TestUser) -> Box<dyn AuthUser> {
    Box::new(u)
}

#[async_trait]
impl UserStore for MemStore {
    async fn find_by_id(&self, user_id: &str) -> Result<Option<Box<dyn AuthUser>>, BoxError> {
        self.find_by_id_calls.fetch_add(1, SeqCst);
        Ok(self.users.lock().unwrap().get(user_id).cloned().map(boxed))
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<Box<dyn AuthUser>>, BoxError> {
        let users = self.users.lock().unwrap();
        Ok(users
            .values()
            .find(|u| u.email == email)
            .cloned()
            .map(boxed))
    }

    // the service only normalizes emails for lookups, so the store has to save
    // the normalized one itself, and this one does. the duplicate check and the
    // insert happen under one lock, same as a UNIQUE index would
    async fn create_user(
        &self,
        input: &dyn RegisterUserInput,
        pass_hash: String,
    ) -> Result<Box<dyn AuthUser>, BoxError> {
        let email = input.email().trim().to_lowercase();
        let mut users = self.users.lock().unwrap();
        if users.values().any(|u| u.email == email) {
            return Err("unique violation".into());
        }
        let id = format!("u{}", self.next_id.fetch_add(1, SeqCst) + 1);
        let user = TestUser {
            id: id.clone(),
            email,
            hash: pass_hash,
            verified: false,
        };
        users.insert(id, user.clone());
        Ok(boxed(user))
    }

    async fn update_user(&self, user: Box<dyn AuthUser>) -> Result<Box<dyn AuthUser>, BoxError> {
        let updated = TestUser {
            id: user.id(),
            email: user.email().to_owned(),
            hash: user.password_hash().to_owned(),
            verified: user.is_email_verified(),
        };
        self.users
            .lock()
            .unwrap()
            .insert(updated.id.clone(), updated.clone());
        Ok(boxed(updated))
    }

    async fn delete_user(&self, user_id: &str) -> Result<(), BoxError> {
        self.users.lock().unwrap().remove(user_id);
        Ok(())
    }

    async fn check_email_verified(&self, user_id: &str) -> Result<bool, BoxError> {
        Ok(self
            .users
            .lock()
            .unwrap()
            .get(user_id)
            .map(|u| u.verified)
            .unwrap_or(false))
    }
}

// harness

pub struct Harness {
    pub auth: AuthService,
    pub store: MemStore,
    pub mailer: MemMailer,
    pub ott: MemOtt,
    pub blacklist: MemBlacklist,
    pub tokens: TestTokens,
    pub clock: Clock,
}

impl Harness {
    // no cache
    pub fn new() -> Self {
        Self::build(None)
    }

    pub fn with_cache(cache: MemCache) -> Self {
        Self::build(Some(cache))
    }

    fn build(cache: Option<MemCache>) -> Self {
        let clock = Clock::default();
        let tokens = TestTokens::new(clock.clone(), 900, 604_800);
        let store = MemStore::default();
        let mailer = MemMailer::default();
        let ott = MemOtt::default();
        let blacklist = MemBlacklist::default();

        let mut builder = AuthService::builder()
            .store(store.clone())
            .hasher(FakeHasher)
            .tokens(tokens.clone())
            .blacklist(blacklist.clone())
            .email_sender(mailer.clone())
            .email_templates(TestTemplates)
            .ott_store(ott.clone());
        if let Some(c) = cache {
            builder = builder.user_cache(c);
        }

        Self {
            auth: builder.build().expect("service should build"),
            store,
            mailer,
            ott,
            blacklist,
            tokens,
            clock,
        }
    }

    // token from the last email sent (verify or reset)
    pub fn last_mail_token(&self) -> String {
        self.mailer.last().expect("no email was sent").body
    }

    // waits until n emails have gone out, polls for up to ~2s.
    // needed because request_password_reset sends from a background task now
    pub async fn wait_for_mail(&self, n: usize) {
        for _ in 0..200 {
            if self.mailer.count() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("expected {n} emails, got {}", self.mailer.count());
    }

    // asks for a reset and returns the token from the email
    pub async fn request_reset_token(&self, email: &str) -> String {
        let before = self.mailer.count();
        self.auth
            .request_password_reset(email)
            .await
            .expect("request_password_reset failed");
        self.wait_for_mail(before + 1).await;
        self.last_mail_token()
    }

    // register but don't verify
    pub async fn register(&self, email: &str, password: &str) -> Box<dyn AuthUser> {
        self.auth
            .register(&reg(email, password))
            .await
            .expect("register failed")
    }

    // register + verify, returns the user id
    pub async fn register_verified(&self, email: &str, password: &str) -> String {
        let user = self.register(email, password).await;
        self.auth
            .verify_email(&self.last_mail_token())
            .await
            .expect("verify_email failed");
        user.id()
    }

    pub async fn login(&self, email: &str, password: &str) -> TokenPair {
        self.auth
            .login(email, password)
            .await
            .expect("login failed")
    }
}
