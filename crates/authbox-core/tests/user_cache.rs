mod common;

use authbox_core::errors::AuthError;
use authbox_core::traits::{TokenManager, UserStore};
use common::*;
use serde_json::json;

#[tokio::test]
async fn me_returns_the_user_and_extra_fields_without_a_cache() {
    let h = Harness::new();
    let id = h.register_verified("a@x.com", PW).await;
    let pair = h.login("a@x.com", PW).await;

    let me = h.auth.me(&pair.access_token).await.unwrap();
    assert_eq!(me.id, id);
    assert_eq!(me.email, "a@x.com");
    assert!(me.email_verified);
    assert_eq!(me.extra, Some(json!({ "role": "tester" })));
}

#[tokio::test]
async fn me_never_exposes_the_password_hash() {
    let h = Harness::new();
    h.register_verified("a@x.com", PW).await;
    let pair = h.login("a@x.com", PW).await;

    let me = h.auth.me(&pair.access_token).await.unwrap();
    let json = serde_json::to_string(&me).unwrap();
    assert!(!json.contains("hashed:"), "password hash leaked: {json}");
}

#[tokio::test]
async fn me_requires_a_valid_access_token() {
    let h = Harness::new();
    h.register_verified("a@x.com", PW).await;
    let pair = h.login("a@x.com", PW).await;

    assert!(matches!(
        h.auth.me("garbage").await,
        Err(AuthError::InvalidToken)
    ));
    assert!(matches!(
        h.auth.me(&pair.refresh_token).await,
        Err(AuthError::InvalidToken)
    ));
}

#[tokio::test]
async fn me_without_a_cache_reads_the_store_every_time() {
    let h = Harness::new();
    h.register_verified("a@x.com", PW).await;
    let pair = h.login("a@x.com", PW).await;

    let before = h.store.find_by_id_calls();
    h.auth.me(&pair.access_token).await.unwrap();
    h.auth.me(&pair.access_token).await.unwrap();
    assert_eq!(h.store.find_by_id_calls() - before, 2);
}

#[tokio::test]
async fn me_second_call_is_served_from_the_cache() {
    let cache = MemCache::default();
    let h = Harness::with_cache(cache.clone());
    h.register_verified("a@x.com", PW).await;
    let pair = h.login("a@x.com", PW).await;

    let before = h.store.find_by_id_calls();
    let first = h.auth.me(&pair.access_token).await.unwrap();
    let second = h.auth.me(&pair.access_token).await.unwrap();

    assert_eq!(
        h.store.find_by_id_calls() - before,
        1,
        "second call must not hit the store"
    );
    assert_eq!(cache.len(), 1);
    assert_eq!(first.id, second.id);
    assert_eq!(second.extra, Some(json!({ "role": "tester" })));
}

#[tokio::test]
async fn me_works_when_the_cache_is_down() {
    let h = Harness::with_cache(MemCache::failing());
    h.register_verified("a@x.com", PW).await;
    let pair = h.login("a@x.com", PW).await;

    let me = h.auth.me(&pair.access_token).await.unwrap();
    assert_eq!(me.email, "a@x.com");
}

#[tokio::test]
async fn me_still_rejects_a_revoked_token_when_the_user_is_cached() {
    let h = Harness::with_cache(MemCache::default());
    h.register_verified("a@x.com", PW).await;
    let pair = h.login("a@x.com", PW).await;
    h.auth.me(&pair.access_token).await.unwrap(); // now cached

    h.auth.request_password_reset("a@x.com").await.unwrap();
    h.auth
        .reset_password(&h.last_mail_token(), PW2)
        .await
        .unwrap();

    let res = h.auth.me(&pair.access_token).await;
    assert!(matches!(res, Err(AuthError::InvalidToken)));
}

#[tokio::test]
async fn verify_email_refreshes_a_cached_me() {
    let h = Harness::with_cache(MemCache::default());
    let user = h.register("a@x.com", PW).await; // unverified
    let verify_token = h.last_mail_token();

    // unverified users cannot log in, so mint a token directly
    let access = h.tokens.generate(&user.id()).await.unwrap().access_token;
    assert!(!h.auth.me(&access).await.unwrap().email_verified); // cached as false

    h.auth.verify_email(&verify_token).await.unwrap();

    assert!(
        h.auth.me(&access).await.unwrap().email_verified,
        "stale cache entry survived"
    );
}

#[tokio::test]
async fn verify_email_succeeds_even_if_cache_invalidation_fails() {
    let h = Harness::with_cache(MemCache::failing());
    h.register("a@x.com", PW).await;

    h.auth.verify_email(&h.last_mail_token()).await.unwrap();
    assert!(h.auth.login("a@x.com", PW).await.is_ok());
}

#[tokio::test]
async fn invalidate_user_cache_reports_failure_but_is_a_noop_without_a_cache() {
    let failing = Harness::with_cache(MemCache::failing());
    let res = failing.auth.invalidate_user_cache("u1").await;
    assert!(matches!(res, Err(AuthError::Cache(_))));

    let none = Harness::new();
    assert!(none.auth.invalidate_user_cache("u1").await.is_ok());
}

#[tokio::test]
async fn me_for_a_deleted_user_is_not_found() {
    let h = Harness::new();
    let id = h.register_verified("a@x.com", PW).await;
    let pair = h.login("a@x.com", PW).await;

    h.store.delete_user(&id).await.unwrap();

    let res = h.auth.me(&pair.access_token).await;
    assert!(matches!(res, Err(AuthError::NotFound)));
}
