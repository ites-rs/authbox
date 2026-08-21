# authbox

A lightweight, modular, async-first authentication framework for Rust.

`authbox` provides a flexible authentication system built around traits, pluggable components, and Tokio-ready async APIs.

It is designed for applications that need customizable authentication logic without being locked into a specific database, framework, or storage backend.

---

## Documentation

**Full documentation, guides, examples, and architecture overview available here:**

[AuthBox Docs](https://authbox-docs.vercel.app/)


## Architecture

1. authbox-core (traits + engine)
2. authbox-jwt (JWT provider)
3. authbox-argon2 (password hashing)
4. authbox-redis (ott & jwt blacklisting )
5. authbox-email (email service providers)


## Features

- Secure password hashing with Argon2
- JWT access + refresh token authentication
- Refresh token rotation
- Refresh token revocation / blacklisting
- Email verification flow
- Password reset flow
- One-time token (OTT) support
- Fully async (`tokio`)
- Trait-driven architecture
- Pluggable storage backends
- Framework agnostic
- Test-friendly design
- Builder API for ergonomic setup
- Custom registration DTO support

---

# Installation

```bash
cargo add authbox
```

---


# Recommended Production Stack

| Component | Recommendation |
|---|---|
| Database | PostgreSQL |
| ORM | SQLx or Diesel |
| Cache / Token Store | Redis |
| Runtime | Tokio |
| HTTP Framework | Axum or Actix |
| Password Hashing | Argon2 |

---

# Roadmap

- [x] Async architecture
- [x] JWT authentication
- [x] Refresh token rotation
- [x] Refresh token revocation
- [x] Email verification
- [x] Password reset flow
- [x] One-time token support
- [x] Pluggable storage backends
- [x] Custom registration DTO support
- [x] Any web Framework
- [x] Middlewares [ ** In your authentication Middlewares check use the `is_token_valid()`) method ** ]
---

# License

Apache-2.0
