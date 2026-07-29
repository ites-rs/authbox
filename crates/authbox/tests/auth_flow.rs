mod common;

use authbox::prelude::*;
use common::*;
use redis::AsyncCommands;

/// Helper: safely extract the first OTT token from Redis for a given user
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

#[test]
fn test_password_hashing() {
    let hasher = DefaultHasher;

    let hash = hasher.hash("password123");

    println!("\n=== PASSWORD HASH ===\n{}", hash);

    assert!(hasher.verify("password123", &hash));
    assert!(!hasher.verify("wrong-password", &hash));
}

#[tokio::test]
async fn test_register_and_login_flow() {
    let mut auth = build_test_auth();

    let user = auth
        .register(RegisterDto {
            email: "john@test.com".to_string(),
            password: "password123".to_string(),
            username: Some("john".to_string()),
            phone: None,
            country: None,
            city: None,
            age: None,
        })
        .await
        .unwrap();

    println!("\n=== REGISTER ===\n{:#?}", user);

    assert_eq!(user.email(), "john@test.com");

    let unverified = auth.login("john@test.com", "password123").await;
    assert!(matches!(unverified, Err(LoginError::EmailNotVerified)));

    // Fetch verification token using the USER ID
    let token = get_token(&auth, &user.id()).await;
    auth.verify_email(&token).await.unwrap();

    let tokens = auth.login("john@test.com", "password123").await.unwrap();

    assert!(!tokens.access_token.is_empty());
    assert!(!tokens.refresh_token.is_empty());

    let failed = auth.login("john@test.com", "wrong-password").await;
    assert!(matches!(failed, Err(LoginError::InvalidCredentials)));
}

#[tokio::test]
async fn test_refresh_token_flow() {
    let mut auth = build_test_auth();

    let user = auth
        .register(RegisterDto {
            email: "refresh@test.com".to_string(),
            password: "password123".to_string(),
            username: None,
            phone: None,
            country: None,
            city: None,
            age: None,
        })
        .await
        .unwrap();

    let token = get_token(&auth, &user.id()).await;
    auth.verify_email(&token).await.unwrap();

    let login = auth.login("refresh@test.com", "password123").await.unwrap();
    let refreshed = auth.refresh_token(&login.refresh_token).await;

    assert!(refreshed.is_ok());
}

#[tokio::test]
async fn test_refresh_token_blacklist_flow() {
    let mut auth = build_test_auth();

    let user = auth
        .register(RegisterDto {
            email: "blacklist@test.com".to_string(),
            password: "password123".to_string(),
            username: None,
            phone: None,
            country: None,
            city: None,
            age: None,
        })
        .await
        .unwrap();

    let token = get_token(&auth, &user.id()).await;
    auth.verify_email(&token).await.unwrap();

    let login = auth
        .login("blacklist@test.com", "password123")
        .await
        .unwrap();

    let refresh_token = login.refresh_token.clone();

    let first = auth.refresh_token(&refresh_token).await;
    assert!(first.is_ok());

    let second = auth.refresh_token(&refresh_token).await;
    assert!(matches!(second, Err(AuthError::BlacklistedToken)));
}