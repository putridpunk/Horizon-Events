"""Sign-in: users, roles, sessions, lock-out and the audit trail. No web framework imports."""
from __future__ import annotations

import hashlib
import os
import re
import secrets
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.auth import passwords
from app.database.auth_models import AuditRow, AuthSessionRow, UserRow
from app.domain import utcnow

ROLES = ("viewer", "analyst", "admin")
RANK = {r: i for i, r in enumerate(ROLES)}
SESSION_IDLE = timedelta(hours=12)
SESSION_MAX = timedelta(days=7)
TOUCH_EVERY = timedelta(minutes=1)
MAX_FAILURES = 5
LOCK_FOR = timedelta(minutes=15)
MAX_AUDIT_DETAIL = 300
_USERNAME = re.compile(r"^[a-z0-9][a-z0-9_.@-]{2,63}$")


class AuthError(ValueError):
    """A request that cannot be accepted; the message is shown to the user."""


class Locked(AuthError):
    pass


def enabled() -> bool:
    """Sign-in applies to server installs only: the desktop app already admits nobody but its own window."""
    return os.environ.get("HORIZON_AUTH") == "1" and os.environ.get("HORIZON_DESKTOP") != "1"


def clean_username(value: str) -> str:
    name = (value or "").strip().lower()
    if not _USERNAME.match(name):
        raise AuthError("A user name has 3 to 64 letters, digits, dots, dashes, underscores or @, and starts with a letter or digit.")
    return name


def audit(session: Session, actor: str | None, action: str, detail: str = "", ip: str | None = None) -> None:
    session.add(AuditRow(at=utcnow(), actor=actor, action=action, detail=detail[:MAX_AUDIT_DETAIL], ip=ip))


def user_count(session: Session) -> int:
    return session.scalar(select(func.count()).select_from(UserRow)) or 0


def active_admins(session: Session) -> int:
    return session.scalar(select(func.count()).select_from(UserRow).where(UserRow.role == "admin", UserRow.disabled.is_(False))) or 0


def create_user(session: Session, username: str, password: str, role: str) -> UserRow:
    name = clean_username(username)
    if role not in ROLES:
        raise AuthError(f"The role must be one of: {', '.join(ROLES)}.")
    try:
        passwords.check_policy(password, name)
    except passwords.PasswordError as exc:
        raise AuthError(str(exc)) from exc
    if session.scalar(select(UserRow.id).where(UserRow.username == name)) is not None:
        raise AuthError("That user name is already taken.")
    user = UserRow(username=name, password_hash=passwords.hash_password(password), role=role, created_at=utcnow())
    session.add(user)
    session.flush()
    return user


def authenticate(session: Session, username: str, password: str, now: datetime | None = None) -> UserRow | None:
    """The user if the credentials are right, else None. Five failures lock the account for 15 minutes.
    Raises Locked while an account is locked (even for the right password, so guessing is pointless)."""
    now = now or utcnow()
    user = session.scalar(select(UserRow).where(UserRow.username == (username or "").strip().lower()))
    if user is None:
        passwords.burn_time(password or "")
        return None
    if user.locked_until and user.locked_until > now:
        raise Locked("This account is locked for a while after too many wrong passwords. Try again later.")
    if user.disabled or not passwords.verify_password(password or "", user.password_hash):
        if not user.disabled:
            user.failed_attempts = (user.failed_attempts or 0) + 1
            if user.failed_attempts >= MAX_FAILURES:
                user.locked_until, user.failed_attempts = now + LOCK_FOR, 0
        return None
    user.failed_attempts, user.locked_until, user.last_login = 0, None, now
    return user


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def start_session(session: Session, user: UserRow, now: datetime | None = None) -> str:
    """Create a sign-in session and return the secret that goes in the cookie (only its hash is stored)."""
    now = now or utcnow()
    token = secrets.token_urlsafe(32)
    session.add(AuthSessionRow(token_hash=_hash_token(token), user_id=user.id, created_at=now, last_seen=now,
                               expires_at=now + SESSION_MAX))
    session.execute(delete(AuthSessionRow).where(AuthSessionRow.expires_at < now))  # tidy up old ones
    return token


def resolve_session(session: Session, token: str | None, now: datetime | None = None) -> UserRow | None:
    """The signed-in user for a cookie value, or None. Idle sessions expire after 12 hours, all after 7 days."""
    if not token:
        return None
    now = now or utcnow()
    row = session.get(AuthSessionRow, _hash_token(token))
    if row is None:
        return None
    user = session.get(UserRow, row.user_id)
    if now > row.expires_at or now - row.last_seen > SESSION_IDLE or user is None or user.disabled:
        session.delete(row)
        return None
    if now - row.last_seen > TOUCH_EVERY:
        row.last_seen = now
    return user


def end_session(session: Session, token: str | None) -> None:
    if token:
        session.execute(delete(AuthSessionRow).where(AuthSessionRow.token_hash == _hash_token(token)))


def end_all_sessions(session: Session, user_id: int, keep_token: str | None = None) -> None:
    stmt = delete(AuthSessionRow).where(AuthSessionRow.user_id == user_id)
    if keep_token:
        stmt = stmt.where(AuthSessionRow.token_hash != _hash_token(keep_token))
    session.execute(stmt)


def set_password(session: Session, user: UserRow, password: str) -> None:
    try:
        passwords.check_policy(password, user.username)
    except passwords.PasswordError as exc:
        raise AuthError(str(exc)) from exc
    user.password_hash = passwords.hash_password(password)
    user.failed_attempts, user.locked_until = 0, None


def can_remove_admin(session: Session, user: UserRow) -> bool:
    """False if removing, disabling or demoting `user` would leave nobody who can manage the others."""
    return not (user.role == "admin" and not user.disabled and active_admins(session) <= 1)


def bootstrap_from_environment(session: Session) -> bool:
    """HORIZON_ADMIN_USER and HORIZON_ADMIN_PASSWORD create the first administrator, for unattended installs."""
    name, password = os.environ.get("HORIZON_ADMIN_USER", ""), os.environ.get("HORIZON_ADMIN_PASSWORD", "")
    if not (name and password) or user_count(session):
        return False
    create_user(session, name, password, "admin")
    audit(session, name.lower(), "setup", "first administrator created from the environment")
    session.commit()
    return True
