"""DI dependencies — extract + verify access tokens from incoming requests."""

from __future__ import annotations

from typing import Any

from hawkapi.exceptions import HTTPException
from hawkapi.requests.request import Request

from hawkapi_auth._tokens import TokenError


def _bearer_token(request: Request) -> str | None:
    auth = request.headers.get("authorization")
    if not auth:
        return None
    parts = auth.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


def _issuer_from_request(request: Request) -> Any:
    from hawkapi_auth._plugin import resolve_issuer  # noqa: PLC0415

    return resolve_issuer(request.scope.get("app"))


async def requires_user(request: Request) -> str:
    """DI helper: validate the ``Authorization: Bearer <jwt>`` header.

    Returns the ``sub`` claim of the access token. Raises ``HTTPException(401)``
    on missing / invalid / revoked tokens.

    Usage:
        @app.get("/me")
        async def me(user_id: str = Depends(requires_user)):
            return await db.fetch_user(user_id)
    """
    token = _bearer_token(request)
    if token is None:
        raise HTTPException(
            401, detail="Missing bearer token", headers={"WWW-Authenticate": "Bearer"}
        )
    issuer = _issuer_from_request(request)
    if issuer is None:
        raise HTTPException(500, detail="hawkapi-auth not initialised")
    try:
        claims = issuer.verify_access(token)
    except TokenError as exc:
        raise HTTPException(401, detail=str(exc), headers={"WWW-Authenticate": "Bearer"}) from exc
    sub = claims.get("sub")
    if not isinstance(sub, str):
        raise HTTPException(401, detail="Token has no subject")
    return sub


async def requires_claims(request: Request) -> dict[str, Any]:
    """DI helper that returns the full set of verified claims, not just ``sub``."""
    token = _bearer_token(request)
    if token is None:
        raise HTTPException(
            401, detail="Missing bearer token", headers={"WWW-Authenticate": "Bearer"}
        )
    issuer = _issuer_from_request(request)
    if issuer is None:
        raise HTTPException(500, detail="hawkapi-auth not initialised")
    try:
        return issuer.verify_access(token)
    except TokenError as exc:
        raise HTTPException(401, detail=str(exc), headers={"WWW-Authenticate": "Bearer"}) from exc


def requires_scopes(*required: str):
    """Build a DI dependency that gates on the ``scope`` claim.

    The access token must carry a ``scope`` claim — either a space-separated
    string (OAuth2 style) or a list of strings. All entries in *required* must
    be present.

    Usage:
        @app.get("/admin", dependencies=[Depends(requires_scopes("admin"))])
        async def admin(): ...
    """

    async def _dep(request: Request) -> dict[str, Any]:
        claims = await requires_claims(request)
        raw = claims.get("scope") or claims.get("scopes") or []
        granted: set[str] = set()
        if isinstance(raw, str):
            granted = set(raw.split())
        elif isinstance(raw, list):
            granted = {s for s in raw if isinstance(s, str)}
        missing = [s for s in required if s not in granted]
        if missing:
            raise HTTPException(403, detail=f"Missing scopes: {', '.join(missing)}")
        return claims

    return _dep


__all__ = ["requires_user", "requires_claims", "requires_scopes"]
