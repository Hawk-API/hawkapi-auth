"""Password hashing helpers."""

from __future__ import annotations

from hawkapi_auth import hash_password, needs_rehash, verify_password


def test_hash_then_verify_roundtrip() -> None:
    h = hash_password("hunter2")
    assert verify_password("hunter2", h) is True


def test_verify_rejects_wrong_password() -> None:
    h = hash_password("hunter2")
    assert verify_password("nope", h) is False


def test_verify_rejects_garbage_hash() -> None:
    assert verify_password("anything", "not-a-hash") is False


def test_hashes_differ_for_same_password() -> None:
    # argon2 includes a random salt — two hashes of the same password must differ.
    a = hash_password("x")
    b = hash_password("x")
    assert a != b


def test_needs_rehash_false_for_fresh_hash() -> None:
    assert needs_rehash(hash_password("x")) is False


def test_needs_rehash_false_for_garbage() -> None:
    assert needs_rehash("garbage") is False
