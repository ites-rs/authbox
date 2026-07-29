mod common;

use authbox::prelude::*;
use common::*;
use redis::AsyncCommands;

/// Helper: fetch the first OTT token for a given user from Redis
async fn get_token(auth: &TestAuthService, user_id: &str) -> String {
    let mut conn = auth
        .ott_store
        .client
        .get_multiplexed_async_connection()
        .await
        .expect("Failed to get Redis connection");

    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("*")
        .query_async(&mut conn)
        .await
        .expect("Failed to fetch keys from Redis");

    for key in keys {
        if let Ok(Some(value)) = conn.get::<_, Option<String>>(&key).await {
            if value == user_id {
                return key;
            }
        }
    }

    panic!("OTT token not found for user {}", user_id);
}

#[tokio::test]
async fn test_email_verification_flow() {
    let mut auth = build_test_auth();

    let user = auth
        .register(RegisterDto {
            email: "verify@test.com".to_string(),
            password: "password123".to_string(),
            username: None,
            phone: None,
            country: None,
            city: None,
            age: None,
        })
        .await
        .expect("registration failed");

    assert!(!user.is_email_verified());

    // Use USER ID, not email.
    let token = get_token(&auth, &user.id()).await;

    println!("\n=== VERIFY TOKEN ===\n{}", token);

    auth.verify_email(&token).await.unwrap();

    let updated = auth
        .store
        .find_by_email("verify@test.com")
        .await
        .unwrap();

    assert!(updated.is_email_verified());
}

#[tokio::test]
async fn test_password_reset_flow() {
    let mut auth = build_test_auth();

    let user = auth
        .register(RegisterDto {
            email: "reset@test.com".to_string(),
            password: "old-password".to_string(),
            username: None,
            phone: None,
            country: None,
            city: None,
            age: None,
        })
        .await
        .expect("registration failed");

    // Verify manually
    let mut verified_user = auth
        .store
        .find_by_id(&user.id())
        .await
        .unwrap();

    verified_user.set_email_verified(true);
    auth.store.update_user(verified_user).await.unwrap();

    auth.request_password_reset("reset@test.com")
        .await
        .expect("password reset request failed");

    // Use USER ID, not email.
    let token = get_token(&auth, &user.id()).await;

    println!("\n=== RESET TOKEN ===\n{}", token);

    auth.reset_password(&token, "new-password")
        .await
        .expect("password reset failed");

    let tokens = auth
        .login("reset@test.com", "new-password")
        .await
        .expect("login failed");

    assert!(!tokens.access_token.is_empty());
    assert!(!tokens.refresh_token.is_empty());
}