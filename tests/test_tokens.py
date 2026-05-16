"""JWT issue + verify + refresh + revocation."""

from __future__ import annotations

import time

import pytest

from hawkapi_auth import (
    JWTConfig,
    RevocationList,
    TokenError,
    TokenIssuer,
    random_secret,
)


@pytest.fixture
def issuer() -> TokenIssuer:
    return TokenIssuer(config=JWTConfig(secret=random_secret()))


def test_access_roundtrip(issuer: TokenIssuer) -> None:
    token = issuer.issue_access("user-1")
    claims = issuer.verify_access(token)
    assert claims["sub"] == "user-1"
    assert claims["type"] == "access"


def test_refresh_roundtrip(issuer: TokenIssuer) -> None:
    token = issuer.issue_refresh("user-1")
    claims = issuer.verify_refresh(token)
    assert claims["sub"] == "user-1"
    assert claims["type"] == "refresh"


def test_access_token_rejected_as_refresh(issuer: TokenIssuer) -> None:
    token = issuer.issue_access("user-1")
    with pytest.raises(TokenError):
        issuer.verify_refresh(token)


def test_refresh_token_rejected_as_access(issuer: TokenIssuer) -> None:
    token = issuer.issue_refresh("user-1")
    with pytest.raises(TokenError):
        issuer.verify_access(token)


def test_garbage_token_rejected(issuer: TokenIssuer) -> None:
    with pytest.raises(TokenError):
        issuer.verify_access("not.a.jwt")


def test_extra_claims_carried_through(issuer: TokenIssuer) -> None:
    token = issuer.issue_access("u", role="admin", scope="read write")
    claims = issuer.verify_access(token)
    assert claims["role"] == "admin"
    assert claims["scope"] == "read write"


def test_audience_required_when_configured() -> None:
    issuer = TokenIssuer(config=JWTConfig(secret=random_secret(), audience="api"))
    token = issuer.issue_access("u")
    assert issuer.verify_access(token)["aud"] == "api"


def test_issuer_required_when_configured() -> None:
    issuer = TokenIssuer(config=JWTConfig(secret=random_secret(), issuer="hawk"))
    token = issuer.issue_access("u")
    assert issuer.verify_access(token)["iss"] == "hawk"


def test_revoked_refresh_rejected() -> None:
    rev = RevocationList()
    issuer = TokenIssuer(config=JWTConfig(secret=random_secret()), revocation=rev)
    token = issuer.issue_refresh("u")
    issuer.revoke_refresh(token)
    with pytest.raises(TokenError, match="revoked"):
        issuer.verify_refresh(token)


def test_revoke_without_revocation_list_errors() -> None:
    issuer = TokenIssuer(config=JWTConfig(secret=random_secret()))
    token = issuer.issue_refresh("u")
    with pytest.raises(TokenError, match="RevocationList"):
        issuer.revoke_refresh(token)


def test_revocation_list_sweeps_expired_entries() -> None:
    rev = RevocationList()
    # Insert a long-expired jti — should disappear on next access.
    rev._store["dead-jti"] = int(time.time()) - 100  # noqa: SLF001
    rev.is_revoked("anything")
    assert "dead-jti" not in rev._store  # noqa: SLF001


def test_jti_unique_per_token(issuer: TokenIssuer) -> None:
    t1 = issuer.issue_access("u")
    t2 = issuer.issue_access("u")
    c1 = issuer.verify_access(t1)
    c2 = issuer.verify_access(t2)
    assert c1["jti"] != c2["jti"]


def test_random_secret_length() -> None:
    s = random_secret()
    assert len(s) >= 64
