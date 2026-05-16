# Changelog

## 0.1.0 — 2026-05-16

Initial release.

- JWT access + refresh tokens (HS256/384/512, RS*, ES*).
- argon2id password hashing with `needs_rehash`.
- DI guards: `requires_user`, `requires_claims`, `requires_scopes`.
- In-memory `RevocationList` with lazy expiry sweep.
- `init_auth(app, config=...)` plugin entry point.
