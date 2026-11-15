# authbox — Actix Web example

A complete Actix Web integration for [authbox](https://github.com/ites-rs/authbox). Covers every auth flow out of the box: register, login, email verification, password reset, token refresh, change password, account deletion, and logout from one or all devices.

## Project structure

```
src/
├── bin/main.rs              — entry point
├── lib.rs                   — server() setup
├── routes.rs                — public and protected route config
├── infrastructure/
│   ├── mod.rs
│   └── state.rs             — AppState (holds AuthService)
└── auth/
    ├── mod.rs
    ├── middleware.rs        — Bearer token validation, injects Claims
    ├── models.rs            — all request DTOs
    ├── utils.rs             — TestStore, MockTemplates, email providers, build_test_auth
    └── handlers/
        ├── register.rs
        ├── login.rs
        ├── verify_email.rs
        ├── request_verify_email.rs
        ├── forgot_password.rs
        ├── reset_password.rs
        ├── refresh_token.rs
        ├── me.rs
        ├── logout.rs
        ├── change_password.rs
        └── delete_account.rs
```

## Running

You need Redis running locally.

```bash
cp .env-sample .env   # fill in your keys
cargo run
# → Server running at http://127.0.0.1:8080
```

## Middleware

`auth/middleware.rs` runs before every route under `/api`. It reads the `Authorization: Bearer <token>` header, calls `auth.is_token_valid()`, and on success injects the `Claims` into request extensions. Handlers under `/api` can grab them with `web::ReqData<Claims>` — no need to touch the token again.

```rust
// routes.rs — this is all it takes to protect a scope
web::scope("/api")
    .wrap(from_fn(auth_middleware))
    .service(me)
    .service(logout_all)
    .service(change_password)
    .service(delete_account)
```

If the token is missing or invalid the middleware short-circuits with `401` before the handler even runs.

## Routes

| Method | Path | Auth | What it does |
|--------|------|------|-------------|
| POST | `/register` | — | Create account, sends verification email |
| POST | `/login` | — | Check credentials, return token pair |
| POST | `/verify-email` | — | Verify email with one-time token |
| POST | `/resend-verification` | — | Re-send verification email |
| POST | `/forgot-password` | — | Send password reset email |
| POST | `/reset-password` | — | Set new password with reset token |
| POST | `/refresh` | — | Rotate refresh token, get new pair |
| POST | `/logout` | — | Blacklist a single refresh token |
| GET | `/api/me` | ✓ | Get current user |
| POST | `/api/logout/all` | ✓ | Revoke every session |
| POST | `/api/change-password` | ✓ | Change password (re-auth required after) |
| POST | `/api/delete-account` | ✓ | Delete account permanently |

## curl examples

### Register

```bash
curl -s -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "supersecretpassword1",
    "username": "syntax",
    "country": "KE"
  }' | jq
```

### Login

```bash
curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "supersecretpassword1"
  }' | jq
```

Save the tokens:

```bash
ACCESS=$(curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"supersecretpassword1"}' \
  | jq -r '.access_token')

REFRESH=$(curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"supersecretpassword1"}' \
  | jq -r '.refresh_token')
```

### Verify email

The token is printed to stdout in dev (see `MockTemplates` in `auth/utils.rs`).

```bash
curl -s -X POST http://localhost:8080/verify-email \
  -H "Content-Type: application/json" \
  -d '{"token": "<token from stdout>"}' | jq
```

### Re-send verification email

Always returns 200 regardless of whether the address exists.

```bash
curl -s -X POST http://localhost:8080/resend-verification \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}' | jq
```

### Forgot password

Always returns 200 regardless of whether the address exists.

```bash
curl -s -X POST http://localhost:8080/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}' | jq
```

### Reset password

```bash
curl -s -X POST http://localhost:8080/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "<token from stdout>",
    "password": "newpassword12345"
  }' | jq
```

### Refresh tokens

```bash
curl -s -X POST http://localhost:8080/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"$REFRESH\"}" | jq
```

### Logout (single device)

```bash
curl -s -X POST http://localhost:8080/logout \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"$REFRESH\"}" | jq
```

### Me

```bash
curl -s http://localhost:8080/api/me \
  -H "Authorization: Bearer $ACCESS" | jq
```

### Logout all devices

```bash
curl -s -X POST http://localhost:8080/api/logout/all \
  -H "Authorization: Bearer $ACCESS" | jq
```

### Change password

All sessions are revoked after — the client must log in again with the new password.

```bash
curl -s -X POST http://localhost:8080/api/change-password \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d '{
    "old_password": "supersecretpassword1",
    "new_password": "evenmoresecretpassword1"
  }' | jq
```

### Delete account

```bash
curl -s -X POST http://localhost:8080/api/delete-account \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d '{"password": "supersecretpassword1"}' | jq
```

## Email providers

Switch providers in `auth/utils.rs` inside `build_test_auth`. Three are included:

| Provider | Env vars needed |
|----------|----------------|
| Resend (default) | `RESEND_API_KEY`, `RESEND_FROM_EMAIL` |
| SendGrid | `SENDGRID_API_KEY`, `SENDGRID_FROM_EMAIL`, `SENDGRID_FROM_NAME` |
| SMTP | `SMTP_HOST`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_EMAIL` |

In dev the token is also printed to stdout so you don't need a real email provider to test.