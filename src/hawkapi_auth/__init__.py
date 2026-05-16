"""hawkapi-auth — JWT auth (access + refresh) + password hashing for HawkAPI."""

from __future__ import annotations

__version__ = "0.1.0"

from hawkapi_auth._deps import requires_claims, requires_scopes, requires_user
from hawkapi_auth._passwords import hash_password, needs_rehash, verify_password
from hawkapi_auth._plugin import init_auth
from hawkapi_auth._tokens import (
    JWTConfig,
    RevocationList,
    TokenError,
    TokenIssuer,
    random_secret,
)

__all__ = [
    "JWTConfig",
    "RevocationList",
    "TokenError",
    "TokenIssuer",
    "__version__",
    "hash_password",
    "init_auth",
    "needs_rehash",
    "random_secret",
    "requires_claims",
    "requires_scopes",
    "requires_user",
    "verify_password",
]
