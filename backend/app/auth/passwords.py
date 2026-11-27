"""Password storage and rules. Passwords are never stored or logged: only a salted PBKDF2-HMAC-SHA256 hash."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

ITERATIONS = 600_000  # OWASP's 2023 guidance for PBKDF2-HMAC-SHA256
MIN_LENGTH = 12
MAX_LENGTH = 200  # a limit on what is hashed, so a huge "password" cannot be used to burn CPU


class PasswordError(ValueError):
    """A password that is not acceptable; the message is shown to the user."""


def check_policy(password: str, username: str = "") -> None:
    if not isinstance(password, str) or len(password) < MIN_LENGTH:
        raise PasswordError(f"Use a password of at least {MIN_LENGTH} characters. A few ordinary words make a good one.")
    if len(password) > MAX_LENGTH:
        raise PasswordError(f"A password can have at most {MAX_LENGTH} characters.")
    if username and password.lower() == username.lower():
        raise PasswordError("The password must not be the same as the user name.")
    if len(set(password)) < 5:
        raise PasswordError("That password is too repetitive. Use a longer mix of characters.")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def hash_password(password: str, iterations: int = ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check. Any malformed hash simply fails."""
    try:
        scheme, iterations, salt, digest = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        expected = base64.b64decode(digest)
        actual = hashlib.pbkdf2_hmac("sha256", password[:MAX_LENGTH].encode("utf-8"), base64.b64decode(salt), int(iterations))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


# Verified when the user name is unknown, so that "no such user" takes as long as "wrong password".
_DUMMY = hash_password("not-a-real-password", iterations=ITERATIONS)


def burn_time(password: str) -> None:
    verify_password(password, _DUMMY)
