"""``init_auth`` — wires a JWT issuer into the HawkAPI app."""

from __future__ import annotations

from typing import Any

from hawkapi_auth._tokens import JWTConfig, RevocationList, TokenIssuer


class _StateNamespace:
    """Lightweight attribute bag for ``app.state`` when none exists."""

    auth: Any  # set by init_auth


_ACTIVE_ISSUERS: dict[int, TokenIssuer] = {}
_LAST_ISSUER: list[TokenIssuer | None] = [None]


def resolve_issuer(app: Any) -> TokenIssuer | None:
    """Look up the active TokenIssuer for *app*, or the last-attached as a fallback.

    Mirrors the lookup pattern from hawkapi-cache: TestClient does not populate
    ``scope["app"]``, so the DI dependency uses a module-level registry.
    """
    if app is not None:
        issuer = _ACTIVE_ISSUERS.get(id(app))
        if issuer is not None:
            return issuer
    return _LAST_ISSUER[0]


def init_auth(
    app: Any,
    *,
    config: JWTConfig,
    revocation: RevocationList | None = None,
) -> TokenIssuer:
    """Mount a :class:`TokenIssuer` on ``app.state.auth`` and register lookup.

    ```python
    from hawkapi import HawkAPI
    from hawkapi_auth import init_auth, JWTConfig, random_secret

    app = HawkAPI()
    init_auth(app, config=JWTConfig(secret=random_secret()))
    ```

    After this call:

    * ``app.state.auth`` is the :class:`TokenIssuer`.
    * ``Depends(requires_user)`` resolves the ``sub`` claim from
      ``Authorization: Bearer …`` headers.
    """
    issuer = TokenIssuer(config=config, revocation=revocation)
    if getattr(app, "state", None) is None:
        app.state = _StateNamespace()
    app.state.auth = issuer
    _ACTIVE_ISSUERS[id(app)] = issuer
    _LAST_ISSUER[0] = issuer
    return issuer


__all__ = ["init_auth", "resolve_issuer"]
