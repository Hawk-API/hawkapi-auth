# hawkapi-auth

JWT auth for [HawkAPI](https://github.com/Hawk-API/HawkAPI). Access + refresh tokens, argon2id password hashing, DI guards, scope-based access control.

## Install

```bash
pip install hawkapi-auth
```

## Quickstart

```python
from hawkapi import Depends, HawkAPI, HTTPException
from hawkapi_auth import (
    JWTConfig,
    hash_password,
    init_auth,
    random_secret,
    requires_user,
    verify_password,
)

app = HawkAPI()
init_auth(app, config=JWTConfig(secret=random_secret()))


@app.post("/register")
async def register(email: str, password: str):
    await db.create_user(email=email, password_hash=hash_password(password))
    return {"ok": True}


@app.post("/login")
async def login(email: str, password: str):
    user = await db.find_user(email)
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(401, detail="Invalid credentials")
    issuer = app.state.auth
    return {
        "access_token": issuer.issue_access(user.id),
        "refresh_token": issuer.issue_refresh(user.id),
    }


@app.get("/me")
async def me(user_id: str = Depends(requires_user)):
    return await db.fetch_user(user_id)
```

## Token issue / verify

```python
issuer = app.state.auth      # TokenIssuer

access = issuer.issue_access("user-1", role="admin", scope="read write")
refresh = issuer.issue_refresh("user-1")

claims = issuer.verify_access(access)        # raises TokenError on bad token
claims = issuer.verify_refresh(refresh)      # ditto, plus checks the token type
```

`issue_access` / `issue_refresh` accept arbitrary keyword claims (`role`, `scope`, anything JSON-serialisable).

## JWTConfig

```python
JWTConfig(
    secret="…",                  # HMAC secret for HS256/384/512
    algorithm="HS256",
    access_ttl_seconds=15 * 60,
    refresh_ttl_seconds=30 * 24 * 60 * 60,
    issuer="my-service",          # optional iss claim
    audience="my-api",            # optional aud claim
    private_key="",               # RS*/ES* — PEM
    public_key="",
)
```

Use `random_secret()` to mint one. Store it outside of git.

## DI guards

```python
from hawkapi_auth import requires_user, requires_claims, requires_scopes

@app.get("/me")
async def me(user_id: str = Depends(requires_user)):
    ...

@app.get("/dump")
async def dump(claims: dict = Depends(requires_claims)):
    ...

@app.get("/admin", dependencies=[Depends(requires_scopes("admin"))])
async def admin():
    ...
```

`requires_scopes(*scopes)` expects either a space-separated `scope` claim or a list under `scope` / `scopes`. Missing scopes → 403.

## Refresh + revocation

```python
from hawkapi_auth import RevocationList

rev = RevocationList()
init_auth(app, config=JWTConfig(secret=...), revocation=rev)

@app.post("/refresh")
async def refresh(refresh_token: str):
    issuer = app.state.auth
    claims = issuer.verify_refresh(refresh_token)
    return {"access_token": issuer.issue_access(claims["sub"])}

@app.post("/logout")
async def logout(refresh_token: str):
    app.state.auth.revoke_refresh(refresh_token)
    return {"ok": True}
```

`RevocationList` is in-memory only. For multi-process deployments, swap in a Redis-backed implementation (planned in v0.2.0).

## Password hashing

```python
from hawkapi_auth import hash_password, verify_password, needs_rehash

h = hash_password("hunter2")              # argon2id
ok = verify_password("hunter2", h)        # constant-time, returns bool
if needs_rehash(h):
    h = hash_password("hunter2")          # re-hash after a successful login
```

`verify_password` never raises — safe to use directly in handler bodies.

## What's not included (v0.2.0 roadmap)

* Social OAuth providers (Google / GitHub / Discord / Microsoft).
* Email-based password reset + verification flows.
* Pre-built user model and storage.
* Redis-backed `RevocationList`.

## Development

```bash
git clone https://github.com/Hawk-API/hawkapi-auth.git
cd hawkapi-auth
uv sync --extra dev
uv run pytest -q
uv run ruff check . && uv run ruff format --check .
uv run pyright src/
```

## License

MIT.
