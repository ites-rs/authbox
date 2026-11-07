use authbox_core::errors::{AuthError, bearer_token};

#[test]
fn bearer_token_parses_a_valid_header() {
    assert_eq!(bearer_token(Some("Bearer abc.def")).unwrap(), "abc.def");
}

#[test]
fn bearer_token_rejects_missing_or_malformed_headers() {
    for header in [
        None,
        Some(""),
        Some("Bearer"),
        Some("Bearer "),
        Some("Bearer    "),
        Some("Basic abc"),
    ] {
        assert!(
            matches!(bearer_token(header), Err(AuthError::MissingToken)),
            "header {header:?} should be rejected"
        );
    }
}

#[test]
fn status_codes() {
    assert_eq!(AuthError::password_length().status(), 400);
    assert_eq!(AuthError::InvalidCredentials.status(), 401);
    assert_eq!(AuthError::InvalidToken.status(), 401);
    assert_eq!(AuthError::BlacklistedToken.status(), 401);
    assert_eq!(AuthError::MissingToken.status(), 401);
    assert_eq!(AuthError::EmailNotVerified.status(), 403);
    assert_eq!(AuthError::NotFound.status(), 404);
    assert_eq!(AuthError::EmailAlreadyExists.status(), 409);
    assert_eq!(AuthError::EmailAlreadyVerified.status(), 409);
    assert_eq!(AuthError::Store("boom".into()).status(), 500);
    assert_eq!(AuthError::Cache("boom".into()).status(), 500);
}

#[test]
fn server_errors_hide_their_details_from_clients() {
    let err = AuthError::Store("connection string with a password".into());
    assert_eq!(err.public_message(), "internal error");

    let err = AuthError::InvalidCredentials;
    assert_eq!(err.public_message(), "invalid credentials");
}

#[test]
fn password_length_message_states_the_limits() {
    let msg = AuthError::password_length().to_string();
    assert!(msg.contains("12") && msg.contains("128"), "got: {msg}");
}
