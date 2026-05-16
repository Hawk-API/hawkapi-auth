"""JWT access + refresh token issue/verify."""

from __future__ import annotations

import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import jwt
from jwt.exceptions import InvalidTokenError


class TokenError(Exception):
    """Raised when a token fails validation."""


@dataclass(frozen=True, slots=True)
class JWTConfig:
    """JWT signing configuration.

    Attributes:
        secret: HMAC secret for symmetric algorithms (HS256/384/512). For RS*
            / ES* use ``private_key`` + ``public_key`` instead.
        algorithm: Signing algorithm. ``HS256`` by default.
        access_ttl_seconds: Lifetime of issued access tokens. 15 minutes default.
        refresh_ttl_seconds: Lifetime of issued refresh tokens. 30 days default.
        issuer: Optional ``iss`` claim.
        audience: Optional ``aud`` claim (string or list of strings).
        private_key: PEM-encoded private key when using asymmetric algorithms.
        public_key: PEM-encoded public key when using asymmetric algorithms.
    """

    secret: str = ""
    algorithm: str = "HS256"
    access_ttl_seconds: int = 15 * 60
    refresh_ttl_seconds: int = 30 * 24 * 60 * 60
    issuer: str | None = None
    audience: str | list[str] | None = None
    private_key: str = ""
    public_key: str = ""
    # Token-type claim values — exposed so consumers can match on them.
    access_type: str = "access"
    refresh_type: str = "refresh"


@dataclass
class TokenIssuer:
    """Issue + verify JWTs against a :class:`JWTConfig`.

    Stateless. For refresh-token revocation use :class:`RevocationList`.
    """

    config: JWTConfig
    revocation: RevocationList | None = None

    def issue_access(self, subject: str, **extra_claims: Any) -> str:
        return self._issue(
            subject, self.config.access_type, self.config.access_ttl_seconds, extra_claims
        )

    def issue_refresh(self, subject: str, **extra_claims: Any) -> str:
        return self._issue(
            subject, self.config.refresh_type, self.config.refresh_ttl_seconds, extra_claims
        )

    def verify_access(self, token: str) -> dict[str, Any]:
        return self._verify(token, expected_type=self.config.access_type)

    def verify_refresh(self, token: str) -> dict[str, Any]:
        return self._verify(token, expected_type=self.config.refresh_type)

    def revoke_refresh(self, token: str) -> None:
        if self.revocation is None:
            raise TokenError("no RevocationList configured")
        claims = self._verify(token, expected_type=self.config.refresh_type, allow_revoked=True)
        jti = claims.get("jti")
        if not isinstance(jti, str):
            raise TokenError("token has no jti claim")
        exp = int(claims.get("exp", 0))
        self.revocation.revoke(jti, exp)

    def _issue(self, subject: str, token_type: str, ttl: int, extra: dict[str, Any]) -> str:
        now = int(time.time())
        payload: dict[str, Any] = {
            "sub": subject,
            "iat": now,
            "exp": now + ttl,
            "jti": uuid.uuid4().hex,
            "type": token_type,
            **extra,
        }
        if self.config.issuer:
            payload["iss"] = self.config.issuer
        if self.config.audience:
            payload["aud"] = self.config.audience
        key = self.config.private_key or self.config.secret
        if not key:
            raise TokenError("JWTConfig has no secret or private_key")
        return jwt.encode(payload, key, algorithm=self.config.algorithm)

    def _verify(
        self, token: str, *, expected_type: str, allow_revoked: bool = False
    ) -> dict[str, Any]:
        key = self.config.public_key or self.config.secret
        if not key:
            raise TokenError("JWTConfig has no secret or public_key")
        options: dict[str, Any] = {}
        if self.config.audience is None:
            options["verify_aud"] = False
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key,
                algorithms=[self.config.algorithm],
                audience=self.config.audience,
                issuer=self.config.issuer,
                options=options,  # type: ignore[arg-type]
            )
        except InvalidTokenError as exc:
            raise TokenError(str(exc)) from exc
        if claims.get("type") != expected_type:
            raise TokenError(f"expected {expected_type!r} token, got {claims.get('type')!r}")
        if not allow_revoked and self.revocation is not None:
            jti = claims.get("jti")
            if isinstance(jti, str) and self.revocation.is_revoked(jti):
                raise TokenError("token revoked")
        return claims


@dataclass
class RevocationList:
    """In-memory revoked-token registry. Keys are JTI claims; values are expiry.

    Expired entries are dropped lazily on every access. For multi-process
    deployments use a Redis-backed implementation (TODO v0.2.0).
    """

    _store: dict[str, int] = field(default_factory=dict)

    def revoke(self, jti: str, exp_timestamp: int) -> None:
        self._sweep()
        self._store[jti] = exp_timestamp

    def is_revoked(self, jti: str) -> bool:
        self._sweep()
        return jti in self._store

    def _sweep(self) -> None:
        now = int(time.time())
        dead = [k for k, exp in self._store.items() if exp <= now]
        for k in dead:
            self._store.pop(k, None)


def random_secret(length: int = 64) -> str:
    """Return a URL-safe random secret suitable for JWTConfig.secret."""
    return secrets.token_urlsafe(length)


__all__ = [
    "JWTConfig",
    "RevocationList",
    "TokenError",
    "TokenIssuer",
    "random_secret",
]
