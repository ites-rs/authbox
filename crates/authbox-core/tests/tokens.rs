mod common;

use authbox_core::errors::AuthError;
use common::*;

#[tokio::test]
async fn valid_access_token_is_accepted() {
    let h = Harness::new();
    let id = h.register_verified("a@x.com", PW).await;
    let pair = h.login("a@x.com", PW).await;

    let claims = h.auth.is_token_valid(&pair.access_token).await.unwrap();
    assert_eq!(claims.sub, id);
}

#[tokio::test]
async fn garbage_token_is_rejected() {
    let h = Harness::new();
    let res = h.auth.is_token_valid("not-a-token").await;
    assert!(matches!(res, Err(AuthError::InvalidToken)));
}

#[tokio::test]
async fn expired_access_token_is_rejected() {
    let h = Harness::new();
    h.register_verified("a@x.com", PW).await;
    let pair = h.login("a@x.com", PW).await;

    h.clock.advance(901); // access ttl in the harness is 900s
    let res = h.auth.is_token_valid(&pair.access_token).await;
    assert!(matches!(res, Err(AuthError::InvalidToken)));
}

#[tokio::test]
async fn refresh_token_is_rejected_as_access_token() {
    let h = Harness::new();
    h.register_verified("a@x.com", PW).await;
    let pair = h.login("a@x.com", PW).await;

    let res = h.auth.is_token_valid(&pair.refresh_token).await;
    assert!(matches!(res, Err(AuthError::InvalidToken)));
}

#[tokio::test]
async fn access_token_is_rejected_as_refresh_token() {
    let h = Harness::new();
    h.register_verified("a@x.com", PW).await;
    let pair = h.login("a@x.com", PW).await;

    let res = h.auth.refresh_token(&pair.access_token).await;
    assert!(matches!(res, Err(AuthError::InvalidToken)));
}

#[tokio::test]
async fn refresh_rotates_and_old_refresh_token_cannot_be_reused() {
    let h = Harness::new();
    h.register_verified("a@x.com", PW).await;
    let pair = h.login("a@x.com", PW).await;

    let new_pair = h.auth.refresh_token(&pair.refresh_token).await.unwrap();
    assert_ne!(new_pair.refresh_token, pair.refresh_token);
    assert!(h.auth.is_token_valid(&new_pair.access_token).await.is_ok());

    // using the old refresh token again has to fail
    let replay = h.auth.refresh_token(&pair.refresh_token).await;
    assert!(matches!(replay, Err(AuthError::BlacklistedToken)));

    // but the new one still works
    assert!(h.auth.refresh_token(&new_pair.refresh_token).await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_refreshes_exactly_one_wins() {
    let h = Harness::new();
    h.register_verified("a@x.com", PW).await;
    let pair = h.login("a@x.com", PW).await;

    // all 8 requests get past the "is it blacklisted?" check before any of
    // them blacklists the token
    const N: usize = 8;
    h.blacklist.gate_is_blacklisted(N);

    let mut tasks = Vec::new();
    for _ in 0..N {
        let auth = h.auth.clone();
        let token = pair.refresh_token.clone();
        tasks.push(tokio::spawn(async move {
            auth.refresh_token(&token).await.is_ok()
        }));
    }

    let mut wins = 0;
    for t in tasks {
        if t.await.unwrap() {
            wins += 1;
        }
    }
    assert_eq!(wins, 1, "exactly one concurrent refresh may succeed");
}

#[tokio::test]
async fn logout_blacklists_refresh_token_and_is_idempotent() {
    let h = Harness::new();
    h.register_verified("a@x.com", PW).await;
    let pair = h.login("a@x.com", PW).await;

    h.auth.logout(&pair.refresh_token).await.unwrap();
    h.auth.logout(&pair.refresh_token).await.unwrap(); // calling it twice is fine

    let res = h.auth.refresh_token(&pair.refresh_token).await;
    assert!(matches!(res, Err(AuthError::BlacklistedToken)));
}

#[tokio::test]
async fn logout_rejects_an_access_token() {
    let h = Harness::new();
    h.register_verified("a@x.com", PW).await;
    let pair = h.login("a@x.com", PW).await;

    let res = h.auth.logout(&pair.access_token).await;
    assert!(matches!(res, Err(AuthError::InvalidToken)));
}
