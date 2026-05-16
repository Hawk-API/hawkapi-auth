# Changelog

## 0.2.0 — 2026-05-16

Security hardening.

- 401 responses now return a generic ``"Invalid or expired token"`` detail; the
  underlying PyJWT message is logged at DEBUG instead of leaked to clients
  (CWE-201).
- ``TokenIssuer`` rejects HMAC secrets shorter than 32 bytes per RFC 7518 §3.2
  (CWE-1022).
- ``requires_scopes`` uses explicit ``scope`` → ``scopes`` precedence so an
  explicit empty ``scope`` no longer silently falls back (CWE-840).
- ``requires_scopes()`` with no arguments raises ``ValueError`` at construction
  rather than producing a permissive dependency (CWE-284).
- Reserved JWT claims (``exp``, ``iat``, ``jti``, ``type``, ``sub``, ``iss``,
  ``aud``, ``nbf``) supplied via ``extra_claims`` are dropped with a warning
  instead of overwriting issuer-controlled values.
- ``PasswordHasher`` now uses explicit OWASP-aligned argon2id parameters
  (``time_cost=3``, ``memory_cost=65536``, ``parallelism=4``).
- The active-issuer registry uses ``WeakKeyDictionary`` to avoid the ``id(app)``
  ABA hazard.

## 0.1.0 — 2026-05-16

Initial release.

- JWT access + refresh tokens (HS256/384/512, RS*, ES*).
- argon2id password hashing with `needs_rehash`.
- DI guards: `requires_user`, `requires_claims`, `requires_scopes`.
- In-memory `RevocationList` with lazy expiry sweep.
- `init_auth(app, config=...)` plugin entry point.
