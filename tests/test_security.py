"""Regression tests for 0.2.0 hardening fixes."""

from __future__ import annotations

from typing import Any

import pytest
from hawkapi import Depends, HawkAPI
from hawkapi.testing import TestClient

from hawkapi_auth import (
    JWTConfig,
    TokenError,
    TokenIssuer,
    init_auth,
    random_secret,
    requires_scopes,
    requires_user,
)


@pytest.fixture
def app() -> HawkAPI:
    app = HawkAPI(openapi_url=None, docs_url=None, redoc_url=None, scalar_url=None)
    init_auth(app, config=JWTConfig(secret=random_secret()))

    @app.get("/me")
    async def me(user_id: str = Depends(requires_user)) -> dict[str, str]:
        return {"user_id": user_id}

    @app.get("/admin")
    async def admin(c: dict[str, Any] = Depends(requires_scopes("admin"))) -> dict[str, str]:
        return {"who": c["sub"]}

    return app


def test_invalid_token_returns_generic_detail(app: HawkAPI) -> None:
    """No library-internal error message must leak through the 401 detail."""
    client = TestClient(app)
    r = client.get("/me", headers={"Authorization": "Bearer not.a.jwt"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid or expired token"


def test_short_hmac_secret_rejected() -> None:
    """HS256 with <32-byte secret must refuse to issue."""
    issuer = TokenIssuer(config=JWTConfig(secret="abc"))
    with pytest.raises(TokenError, match="HMAC secret"):
        issuer.issue_access("u")


def test_scope_takes_precedence_over_scopes(app: HawkAPI) -> None:
    """Explicit empty ``scope`` must NOT silently fall back to ``scopes``."""
    issuer = app.state.auth  # type: ignore[attr-defined]
    token = issuer.issue_access("alice", scope="", scopes=["admin"])
    client = TestClient(app)
    r = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403


def test_requires_scopes_zero_args_raises() -> None:
    """``requires_scopes()`` with no scopes is a programmer error."""
    with pytest.raises(ValueError, match="at least one scope"):
        requires_scopes()


def test_extra_claims_cannot_shadow_reserved() -> None:
    """Caller-supplied reserved claims (exp/type/sub/...) must be ignored."""
    issuer = TokenIssuer(config=JWTConfig(secret=random_secret()))
    token = issuer.issue_access("u", exp=0, type="admin", sub="attacker")
    # _verify treats exp=0 as long-expired — caller injection must NOT take effect.
    claims = issuer.verify_access(token)
    assert claims["type"] == "access"
    assert claims["sub"] == "u"
    assert claims["exp"] > 0
