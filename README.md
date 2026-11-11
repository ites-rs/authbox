# authbox

A lightweight, modular, async-first authentication framework for Rust.

`authbox` gives you a complete authentication flow built around traits, pluggable components and Tokio-ready async APIs. You bring your own database, cache and web framework. authbox handles the security logic.

## Documentation

Full documentation, guides and an architecture overview are available here:

[AuthBox Docs](https://authbox-docs.vercel.app/)

## Installation

```bash
cargo add authbox
```

## Architecture

authbox is a workspace of small crates, each with one job. The `authbox` crate bundles them behind one prelude, so most users only need to add that one dependency.

1. authbox: the main crate, re-exports everything through `authbox::prelude`
2. authbox-core: traits and the authentication engine
3. authbox-jwt: JWT access and refresh token provider
4. authbox-argon2: password hashing
5. authbox-redis: one-time token store and JWT blacklist
6. authbox-cache: in-memory user cache built on moka
7. authbox-email: email providers (Resend, SendGrid, SMTP)

### Defaults and custom implementations

Every component is a trait, and each one ships with a default you can use right away. You can also implement the trait yourself and plug in your own.

| Component | Trait | Default implementation |
|---|---|---|
| Password hashing | `PasswordHasher` | `DefaultHasher` (Argon2) |
| Token management | `TokenManager` | `DefaultJwtManager` |
| Token blacklist | `TokenBlacklistStore` | `RedisBlacklistStore` |
| One-time tokens | `OneTimeTokenStore` | `RedisOttStore` |
| User cache | `UserCache` | `DefaultMemoryUserCache` (moka) |
| Email delivery | `EmailProvider` | `ResendEmailProvider`, `SendGridEmailProvider`, `SmtpEmailProvider` |
| User storage | `UserStore` | None, you implement this for your database |
| Email content | `EmailTemplateConfig` | None, you write your own templates |

The user store and the email templates have no default because they depend on your database and your app. The user cache is optional, so you can leave it out or swap in something like a Redis backed cache by implementing `UserCache`.

## Features

* Argon2 password hashing, run on blocking threads so it never stalls the async runtime
* JWT access and refresh tokens
* Refresh token rotation (each refresh token can be used once)
* Refresh token revocation and blacklisting
* Session revocation: invalidate every token a user has issued so far
* Email verification flow
* Password reset flow with 15 minute reset tokens
* Change password for logged in users
* Account deletion with password confirmation
* Logout from a single device or from all devices
* One-time token (OTT) support with atomic claim, so a token cannot be used twice
* Optional user cache for the `me` lookup, with a default in-memory implementation (moka) and a `UserCache` trait for your own, plus hit and miss metrics
* Custom registration DTO support for extra profile fields
* Pluggable storage backends
* Framework agnostic
* Fully async (`tokio`)
* Builder API for ergonomic setup
* Test friendly design, with in-memory fixtures

## Quick start

Build an `AuthService` once at startup and share it across your handlers. It is cheap to clone because it wraps an `Arc` internally.

```rust
use authbox::prelude::*;

let client = redis::Client::open("redis://127.0.0.1/")?;

let auth = AuthService::builder()
    .store(MyUserStore::new())                 // your database, implements UserStore
    .hasher(DefaultHasher)
    .tokens(DefaultJwtManager::new("a-secret-at-least-32-bytes-long!!", None, None)?)
    .blacklist(RedisBlacklistStore::new(client.clone()).await?)
    .email_sender(resend_email_provider())     // or SendGrid, or SMTP
    .email_templates(MyTemplates)              // implements EmailTemplateConfig
    .ott_store(RedisOttStore::new(client))
    .user_cache(DefaultMemoryUserCache::default()) // optional, moka based default from authbox-cache
    .build()?;
```

Then call it from your handlers:

```rust
// sign up, a verification email is sent automatically
auth.register(&dto).await?;

// verify the email using the token from the link
auth.verify_email(&token).await?;

// log in and get an access and refresh token pair
let pair = auth.login("user@example.com", "a-long-password").await?;

// get the current user from an access token
let me = auth.me(&pair.access_token).await?;

// rotate tokens
let new_pair = auth.refresh_token(&pair.refresh_token).await?;

// log out of this device by blacklisting the refresh token
auth.logout(&new_pair.refresh_token).await?;
```

Here is every other method you will use in a real app:

```rust
// validate an access token (use this in your auth middleware)
// returns the Claims, so claims.sub is the user id
let claims = auth.is_token_valid(&access_token).await?;

// forgot password: sends a reset email
// returns Ok(()) even for unknown emails, so always show the same message
auth.request_password_reset("user@example.com").await?;

// reset password using the token from the email link
// this also revokes every existing session for that user
auth.reset_password(&token, "a-new-long-password").await?;

// change password for a logged in user
// take user_id from the validated claims, never from the request body
// all sessions are revoked, so the client must log in again
auth.change_password(&claims.sub, "old-password", "a-new-long-password").await?;

// log out of every device
auth.logout_all(&claims.sub).await?;

// permanently delete the account (password is re-checked first)
auth.delete_account(&claims.sub, "a-long-password").await?;

// clear the cached user entry after you change user data yourself
auth.invalidate_user_cache(&claims.sub).await?;
```

A few things to remember:

* Passwords must be 12 to 128 characters.
* `change_password`, `logout_all` and `delete_account` take a `user_id`. Always pass `claims.sub` from `is_token_valid`, never a value from the request.
* Every method returns `Result<_, AuthError>`, so match on the error to pick the right HTTP status in your handlers (for example `InvalidCredentials`, `EmailNotVerified`, `InvalidToken`, `EmailAlreadyExists`).

## Using it with Actix Web

A complete, working Actix Web integration lives in the `examples` directory. Check it out for the full setup, including shared app state, the auth middleware, and routes for register, login, refresh, verify email, forgot password, reset password, logout, logout all and me.

The important part is the middleware. Protect your routes by calling `is_token_valid()` and passing the claims on to your handlers:

```rust
let claims = state.auth.is_token_valid(&token).await?;
req.extensions_mut().insert(claims);
```

Handlers can then read the user with `web::ReqData<Claims>`.

## API overview

| Method | What it does |
|---|---|
| `register` | Creates a user and sends a verification email. Rolls the user back if the email cannot be sent. |
| `verify_email` | Verifies an email address using a one-time token. |
| `login` | Checks credentials and returns a token pair. |
| `me` | Returns the current user. The token is always validated, only user data is cached. |
| `refresh_token` | Rotates a refresh token and issues a new pair. |
| `request_password_reset` | Sends a reset email. Always returns `Ok` so registered emails cannot be discovered. |
| `reset_password` | Sets a new password using a reset token and revokes all existing sessions. |
| `change_password` | Changes the password for a logged in user and revokes all existing sessions. |
| `delete_account` | Deletes the account after re-checking the password. Sessions are revoked first. |
| `logout` | Blacklists a single refresh token. Safe to call more than once. |
| `logout_all` | Logs the user out of every device. Tokens issued afterwards work normally. |
| `is_token_valid` | Validates an access token. Use this in your middleware. |
| `invalidate_user_cache` | Clears the cached user entry. Call it after you change user data yourself. |

## Security notes

**Session revocation.** Resetting a password, changing a password, deleting an account and calling `logout_all` all void every session issued before that moment. Any token older than the revocation time is rejected, even if it has not expired yet. After `change_password` the caller is logged out too, so the client must log in again with the new password.

**Trusted user ids.** Methods that take a `user_id` (`change_password`, `delete_account`, `logout_all`) must receive it from a validated access token, never from request input.

**Login timing.** A password hash is verified even when the email is unknown, so response times do not reveal which accounts exist. The password is checked before the verification status is revealed.

**Password reset.** `request_password_reset` returns the same result whether or not the email exists, and email send failures are logged instead of returned.

**One-time tokens.** Tokens are claimed atomically with `take`, so two simultaneous requests cannot both use the same token. Verification and reset tokens are namespaced and cannot be swapped for each other. If a temporary failure happens while verifying an email, the token is restored so the user can try again.

**Unique emails.** The duplicate email check in `register` is only a fast path. Your database must have a UNIQUE index on the normalized email column, and your `UserStore::create_user` must report a unique violation as `AuthError::EmailAlreadyExists`. See `map_store_create_err` in the source for how to wire this up for your store.

**Passwords.** Passwords must be between 12 and 128 characters. Emails are trimmed and lowercased before lookup.

## Observability

When a user cache is configured, authbox records these counters through the `metrics` crate:

* `authbox_cache_hits_total`
* `authbox_cache_misses_total`
* `authbox_cache_read_failures_total`
* `authbox_cache_write_failures_total`
* `authbox_cache_invalidate_failures_total`

Cache failures never break a request. authbox logs a warning and falls back to your store.

## Email providers

Three providers are included. Each is configured with your own credentials.

| Provider | Environment variables |
|---|---|
| Resend | `RESEND_API_KEY`, `RESEND_FROM_EMAIL` |
| SendGrid | `SENDGRID_API_KEY`, `SENDGRID_FROM_EMAIL`, `SENDGRID_FROM_NAME` |
| SMTP | `SMTP_HOST`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_EMAIL` |

You can also implement the `EmailProvider` trait to use any other service.

## Testing

The test fixtures include an in-memory `UserStore`, a sample registration DTO with extra profile fields, mock email templates and a helper that builds a full `AuthService`. Clones of the in-memory store share the same data, so a test can pass one copy to the builder and keep another to inspect the results. The helper expects Redis running on `127.0.0.1`.

## Recommended production stack

| Component | Recommendation |
|---|---|
| Database | PostgreSQL |
| ORM | SQLx or Diesel |
| Cache / Token Store | Redis |
| Runtime | Tokio |
| HTTP Framework | Axum or Actix |
| Password Hashing | Argon2 |

## Roadmap

- [x] Async architecture
- [x] JWT authentication
- [x] Refresh token rotation
- [x] Refresh token revocation
- [x] Session revocation on password reset, password change and account deletion
- [x] Logout from all devices
- [x] Email verification
- [x] Password reset flow
- [x] Change password
- [x] Account deletion
- [x] One-time token support
- [x] User cache with metrics
- [x] Pluggable storage backends
- [x] Custom registration DTO support
- [x] Works with any web framework
- [x] Middleware support (use `is_token_valid()` in your authentication middleware)

## License

Apache-2.0