mod common;

use authbox_core::errors::AuthError;
use common::*;

// ------------------------------------------------------------ register ----

#[tokio::test]
async fn register_sends_one_verification_email() {
    let h = Harness::new();
    h.register("a@x.com", PW).await;

    assert_eq!(h.mailer.count(), 1);
    assert_eq!(h.mailer.last().unwrap().to, "a@x.com");
}

#[tokio::test]
async fn duplicate_email_is_rejected_regardless_of_case_or_spaces() {
    let h = Harness::new();
    h.register("a@x.com", PW).await;

    let res = h.auth.register(&reg("  A@X.COM ", PW)).await;
    assert!(matches!(res, Err(AuthError::EmailAlreadyExists)));
    assert_eq!(h.store.user_count(), 1);
}

#[tokio::test]
async fn register_rolls_back_when_the_email_cannot_be_sent() {
    let h = Harness::new();
    h.mailer.set_fail(true);

    let res = h.auth.register(&reg("a@x.com", PW)).await;
    assert!(matches!(res, Err(AuthError::Email(_))));
    assert_eq!(h.store.user_count(), 0, "user must be rolled back");
    assert_eq!(h.ott.len(), 0, "verification token must be rolled back");
}

// ------------------------------------------------------ password policy ----

#[tokio::test]
async fn password_length_is_enforced_on_register() {
    let h = Harness::new();

    for (n, ok) in [(11, false), (12, true), (128, true), (129, false)] {
        let email = format!("user{n}@x.com");
        let res = h.auth.register(&reg(&email, &"p".repeat(n))).await;
        match (ok, res) {
            (true, Ok(_)) => {}
            (false, Err(AuthError::PasswordLength { .. })) => {}
            (expected_ok, other) => {
                panic!(
                    "len {n}: expected ok={expected_ok}, got ok={}",
                    other.is_ok()
                )
            }
        }
    }
}

#[tokio::test]
async fn password_length_counts_characters_not_bytes() {
    let h = Harness::new();

    // 12 chars = 24 bytes -> accepted
    assert!(
        h.auth
            .register(&reg("a@x.com", &"é".repeat(12)))
            .await
            .is_ok()
    );
    // 11 chars = 22 bytes (more than 12 bytes) -> must still be rejected
    let res = h.auth.register(&reg("b@x.com", &"é".repeat(11))).await;
    assert!(matches!(res, Err(AuthError::PasswordLength { .. })));
}

#[tokio::test]
async fn a_rejected_password_creates_no_user() {
    let h = Harness::new();
    let _ = h.auth.register(&reg("a@x.com", "short")).await;
    assert_eq!(h.store.user_count(), 0);
    assert_eq!(h.mailer.count(), 0);
}

// --------------------------------------------------------- verify email ----

#[tokio::test]
async fn unverified_user_cannot_log_in() {
    let h = Harness::new();
    h.register("a@x.com", PW).await;

    let res = h.auth.login("a@x.com", PW).await;
    assert!(matches!(res, Err(AuthError::EmailNotVerified)));
}

#[tokio::test]
async fn wrong_password_on_unverified_account_does_not_reveal_verification_status() {
    let h = Harness::new();
    h.register("a@x.com", PW).await;

    let res = h.auth.login("a@x.com", "wrong-password-123").await;
    assert!(matches!(res, Err(AuthError::InvalidCredentials)));
}

#[tokio::test]
async fn verification_token_works_once() {
    let h = Harness::new();
    h.register("a@x.com", PW).await;
    let token = h.last_mail_token();

    h.auth.verify_email(&token).await.unwrap();
    assert!(h.auth.login("a@x.com", PW).await.is_ok());

    let again = h.auth.verify_email(&token).await;
    assert!(matches!(again, Err(AuthError::InvalidToken)));
}

#[tokio::test]
async fn unknown_verification_token_is_rejected() {
    let h = Harness::new();
    let res = h.auth.verify_email("nope").await;
    assert!(matches!(res, Err(AuthError::InvalidToken)));
}

// ---------------------------------------------------------------- login ----

#[tokio::test]
async fn login_ignores_email_case_and_surrounding_spaces() {
    let h = Harness::new();
    h.register_verified("Bob@Example.com", PW).await;

    assert!(h.auth.login("  bob@example.com ", PW).await.is_ok());
    assert!(h.auth.login("BOB@EXAMPLE.COM", PW).await.is_ok());
}

#[tokio::test]
async fn unknown_email_and_wrong_password_look_identical() {
    let h = Harness::new();
    h.register_verified("a@x.com", PW).await;

    let unknown = h.auth.login("nobody@x.com", PW).await.unwrap_err();
    let wrong = h
        .auth
        .login("a@x.com", "wrong-password-123")
        .await
        .unwrap_err();

    assert!(matches!(unknown, AuthError::InvalidCredentials));
    assert!(matches!(wrong, AuthError::InvalidCredentials));
    assert_eq!(unknown.status(), wrong.status());
    assert_eq!(unknown.to_string(), wrong.to_string());
    assert_eq!(unknown.public_message(), wrong.public_message());
}

// ------------------------------------------------------- password reset ----

#[tokio::test]
async fn reset_request_for_unknown_email_succeeds_silently() {
    let h = Harness::new();
    assert!(h.auth.request_password_reset("nobody@x.com").await.is_ok());
    assert_eq!(
        h.mailer.count(),
        0,
        "no email may be sent for unknown accounts"
    );
}

#[tokio::test]
async fn reset_request_for_known_email_sends_one_email() {
    let h = Harness::new();
    h.register_verified("a@x.com", PW).await;
    let before = h.mailer.count();

    h.auth.request_password_reset("a@x.com").await.unwrap();
    assert_eq!(h.mailer.count(), before + 1);
}

#[tokio::test]
async fn reset_request_still_succeeds_when_email_sending_fails() {
    let h = Harness::new();
    h.register_verified("a@x.com", PW).await;
    h.mailer.set_fail(true);

    // an error here would reveal that the account exists
    assert!(h.auth.request_password_reset("a@x.com").await.is_ok());
}

#[tokio::test]
async fn reset_changes_the_password() {
    let h = Harness::new();
    h.register_verified("a@x.com", PW).await;
    h.auth.request_password_reset("a@x.com").await.unwrap();
    let token = h.last_mail_token();

    h.auth.reset_password(&token, PW2).await.unwrap();

    let old = h.auth.login("a@x.com", PW).await;
    assert!(matches!(old, Err(AuthError::InvalidCredentials)));
    assert!(h.auth.login("a@x.com", PW2).await.is_ok());
}

#[tokio::test]
async fn reset_token_works_once() {
    let h = Harness::new();
    h.register_verified("a@x.com", PW).await;
    h.auth.request_password_reset("a@x.com").await.unwrap();
    let token = h.last_mail_token();

    h.auth.reset_password(&token, PW2).await.unwrap();
    let again = h
        .auth
        .reset_password(&token, "yet-another-password-3")
        .await;
    assert!(matches!(again, Err(AuthError::InvalidToken)));
}

#[tokio::test]
async fn reset_enforces_the_password_policy_without_burning_the_token() {
    let h = Harness::new();
    h.register_verified("a@x.com", PW).await;
    h.auth.request_password_reset("a@x.com").await.unwrap();
    let token = h.last_mail_token();

    let weak = h.auth.reset_password(&token, "short").await;
    assert!(matches!(weak, Err(AuthError::PasswordLength { .. })));

    // the same token still works with a valid password
    assert!(h.auth.reset_password(&token, PW2).await.is_ok());
}

#[tokio::test]
async fn reset_token_is_rejected_as_verify_token() {
    let h = Harness::new();
    h.register("a@x.com", PW).await; // unverified
    h.auth.request_password_reset("a@x.com").await.unwrap();
    let reset_token = h.last_mail_token();

    let res = h.auth.verify_email(&reset_token).await;
    assert!(matches!(res, Err(AuthError::InvalidToken)));
}

#[tokio::test]
async fn verify_token_is_rejected_as_reset_token() {
    let h = Harness::new();
    h.register("a@x.com", PW).await;
    let verify_token = h.last_mail_token();

    let res = h.auth.reset_password(&verify_token, PW2).await;
    assert!(matches!(res, Err(AuthError::InvalidToken)));
}

// ------------------------------------------- sessions revoked on reset ----

#[tokio::test]
async fn password_reset_revokes_existing_sessions() {
    let h = Harness::new();
    h.register_verified("a@x.com", PW).await;
    let old = h.login("a@x.com", PW).await;
    assert!(h.auth.is_token_valid(&old.access_token).await.is_ok());

    h.auth.request_password_reset("a@x.com").await.unwrap();
    h.auth
        .reset_password(&h.last_mail_token(), PW2)
        .await
        .unwrap();

    // the stolen-token scenario: neither token works, and refresh cannot resurrect the session
    let access = h.auth.is_token_valid(&old.access_token).await;
    assert!(matches!(access, Err(AuthError::InvalidToken)));
    let refresh = h.auth.refresh_token(&old.refresh_token).await;
    assert!(matches!(refresh, Err(AuthError::InvalidToken)));

    // a fresh login after the reset works (the clock is moved forward so the
    // new token's `iat` is later than the revoke cutoff)
    h.clock.advance(5);
    let fresh = h.login("a@x.com", PW2).await;
    assert!(h.auth.is_token_valid(&fresh.access_token).await.is_ok());
    assert!(h.auth.refresh_token(&fresh.refresh_token).await.is_ok());
}

#[tokio::test]
async fn password_reset_does_not_affect_other_users() {
    let h = Harness::new();
    h.register_verified("a@x.com", PW).await;
    h.register_verified("b@x.com", PW).await;
    let a = h.login("a@x.com", PW).await;
    let b = h.login("b@x.com", PW).await;

    h.auth.request_password_reset("a@x.com").await.unwrap();
    h.auth
        .reset_password(&h.last_mail_token(), PW2)
        .await
        .unwrap();

    assert!(h.auth.is_token_valid(&a.access_token).await.is_err());
    assert!(h.auth.is_token_valid(&b.access_token).await.is_ok());
}
