"""Password hashing helpers — argon2id by default."""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Return an argon2id hash of *password* (PHC string format)."""
    return _hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time check of *password* against a stored argon2 hash.

    Returns False on mismatch or invalid hash format. Never raises so it is
    safe to use directly in handler logic.
    """
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, Exception):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True when *stored_hash* should be re-hashed with current parameters.

    Call this after a successful login and re-hash the password if it returns
    True — protects against algorithm / parameter upgrades over time.
    """
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except Exception:
        return False


__all__ = ["hash_password", "verify_password", "needs_rehash"]
