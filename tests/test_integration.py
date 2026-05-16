"""End-to-end auth via TestClient — requires_user / requires_scopes."""

from __future__ import annotations

from typing import Any

import pytest
from hawkapi import Depends, HawkAPI
from hawkapi.testing import TestClient

from hawkapi_auth import (
    JWTConfig,
    init_auth,
    random_secret,
    requires_claims,
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

    @app.get("/claims")
    async def claims(c: dict[str, Any] = Depends(requires_claims)) -> dict[str, Any]:
        return {"sub": c.get("sub"), "type": c.get("type")}

    @app.get("/admin")
    async def admin(c: dict[str, Any] = Depends(requires_scopes("admin"))) -> dict[str, str]:
        return {"who": c["sub"]}

    return app


@pytest.fixture
def client(app: HawkAPI) -> TestClient:
    return TestClient(app)


def test_missing_bearer_returns_401(client: TestClient) -> None:
    r = client.get("/me")
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


def test_invalid_token_returns_401(client: TestClient) -> None:
    r = client.get("/me", headers={"Authorization": "Bearer not.a.jwt"})
    assert r.status_code == 401


def test_valid_access_token_unlocks_route(app: HawkAPI, client: TestClient) -> None:
    issuer = app.state.auth  # type: ignore[attr-defined]
    token = issuer.issue_access("alice")
    r = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json() == {"user_id": "alice"}


def test_refresh_token_rejected_on_access_route(app: HawkAPI, client: TestClient) -> None:
    issuer = app.state.auth  # type: ignore[attr-defined]
    token = issuer.issue_refresh("alice")
    r = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_requires_claims_returns_full_payload(app: HawkAPI, client: TestClient) -> None:
    issuer = app.state.auth  # type: ignore[attr-defined]
    token = issuer.issue_access("alice", scope="read")
    r = client.get("/claims", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    assert body["sub"] == "alice"
    assert body["type"] == "access"


def test_requires_scopes_allows_when_scope_present(app: HawkAPI, client: TestClient) -> None:
    issuer = app.state.auth  # type: ignore[attr-defined]
    token = issuer.issue_access("alice", scope="admin read")
    r = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json() == {"who": "alice"}


def test_requires_scopes_denies_when_scope_missing(app: HawkAPI, client: TestClient) -> None:
    issuer = app.state.auth  # type: ignore[attr-defined]
    token = issuer.issue_access("alice", scope="read")
    r = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403


def test_requires_scopes_accepts_list_form(app: HawkAPI, client: TestClient) -> None:
    issuer = app.state.auth  # type: ignore[attr-defined]
    token = issuer.issue_access("alice", scope=["admin", "read"])
    r = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


def test_malformed_authorization_header(client: TestClient) -> None:
    r = client.get("/me", headers={"Authorization": "Basic xxx"})
    assert r.status_code == 401
