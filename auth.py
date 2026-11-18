"""Password hashing helpers for the login demo.

Passwords are never stored in plaintext. Each account keeps a random salt and a
PBKDF2-HMAC-SHA256 hash of the password, exactly like a small production app
would keep them in its database.
"""

from __future__ import annotations

import hashlib
import secrets

ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 120_000


def new_salt() -> str:
    """Return a fresh random salt, hex encoded."""
    return secrets.token_hex(8)


def hash_password(password: str, salt: str) -> str:
    """Return the hex encoded PBKDF2-SHA256 hash of ``password`` and ``salt``."""
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        ITERATIONS,
    )
    return digest.hex()


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """Return True when ``password`` matches the stored ``password_hash``.

    ``password`` is the value the user typed into the login form, ``salt`` is the
    salt stored next to the hash. An empty password or an empty stored hash
    never matches.
    """
    if not password or not password_hash:
        return False
    return hash_password(password, salt) == password_hash
