"""Password hashing and short-lived in-memory teaching sessions.

For a production system, use a vetted identity provider and persistent sessions.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import secrets

ITERATIONS = 250_000


def hash_password(password: str) -> tuple[str, str]:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), ITERATIONS)
    return salt, digest.hex()


def verify_password(password: str, salt: str, expected: str) -> bool:
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), ITERATIONS)
    return hmac.compare_digest(digest.hex(), expected)


@dataclass(frozen=True)
class Principal:
    id: int
    username: str
    role: str


class SessionStore:
    """Demo only: tokens are invalidated when the server stops."""

    def __init__(self):
        self._tokens: dict[str, tuple[Principal, datetime]] = {}

    def create(self, user: Principal) -> str:
        token = secrets.token_urlsafe(32)
        self._tokens[token] = (user, datetime.now(timezone.utc) + timedelta(hours=1))
        return token

    def lookup(self, token: str) -> Principal | None:
        record = self._tokens.get(token)
        if record is None:
            return None
        principal, expires = record
        if datetime.now(timezone.utc) >= expires:
            del self._tokens[token]
            return None
        return principal
