"""Sign in, sign out, users and the audit trail (only active when HORIZON_AUTH=1 on a server install)."""
import os
import secrets

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import service
from app.auth.guard import COOKIE, cookie_value, login_throttle
from app.database.auth_models import AuditRow, UserRow
from app.database.connection import get_session

router = APIRouter(prefix="/api", tags=["auth"])


class Credentials(BaseModel):
    username: str
    password: str


class SetupBody(Credentials):
    token: str


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


class UserCreate(Credentials):
    role: str = "viewer"


class UserUpdate(BaseModel):
    role: str | None = None
    disabled: bool | None = None
    password: str | None = None
    unlock: bool | None = None


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _cookie(request: Request) -> str | None:
    return cookie_value({"cookie": request.headers.get("cookie", "")})


def _set_cookie(request: Request, response: Response, token: str) -> None:
    secure = request.url.scheme == "https" or os.environ.get("HORIZON_COOKIE_SECURE") == "1"
    response.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=secure, path="/",
                        max_age=int(service.SESSION_MAX.total_seconds()))


def _current(request: Request, session: Session) -> UserRow | None:
    user = service.resolve_session(session, _cookie(request))
    return user


def _require_enabled() -> None:
    if not service.enabled():
        raise HTTPException(404, "Sign-in is not turned on.")


def _public(user: UserRow) -> dict:
    return {"username": user.username, "role": user.role}


@router.get("/auth/status")
def status(request: Request, session: Session = Depends(get_session)):
    if not service.enabled():
        return {"enabled": False, "setup_required": False, "user": None}
    user = _current(request, session)
    session.commit()
    return {"enabled": True, "setup_required": service.user_count(session) == 0, "user": _public(user) if user else None}


@router.post("/auth/setup", status_code=201)
def setup(body: SetupBody, request: Request, response: Response, session: Session = Depends(get_session)):
    """Create the first administrator. The one-time code is printed in the server's log when it starts."""
    _require_enabled()
    expected = getattr(request.app.state, "setup_token", None)
    if service.user_count(session) > 0 or not expected:
        raise HTTPException(409, "Setup has already been done.")
    if not login_throttle.allow(f"setup:{_ip(request)}"):
        raise HTTPException(429, "Too many attempts. Wait a few minutes.")
    if not secrets.compare_digest(body.token.strip(), expected):
        service.audit(session, None, "setup_failed", "wrong setup code", _ip(request))
        session.commit()
        raise HTTPException(403, "That setup code is not right. Look for it in the server's log.")
    try:
        user = service.create_user(session, body.username, body.password, "admin")
    except service.AuthError as exc:
        raise HTTPException(422, str(exc)) from exc
    request.app.state.setup_token = None  # single use
    service.audit(session, user.username, "setup", "first administrator created", _ip(request))
    _set_cookie(request, response, service.start_session(session, user))
    session.commit()
    return {"user": _public(user)}


@router.post("/auth/login")
def login(body: Credentials, request: Request, response: Response, session: Session = Depends(get_session)):
    _require_enabled()
    ip = _ip(request)
    if not login_throttle.allow(f"login:{ip}"):
        raise HTTPException(429, "Too many sign-in attempts from this address. Wait a few minutes.")
    try:
        user = service.authenticate(session, body.username, body.password)
    except service.Locked as exc:
        service.audit(session, body.username.strip().lower()[:64], "login_locked", "", ip)
        session.commit()
        raise HTTPException(429, str(exc)) from exc
    if user is None:
        service.audit(session, body.username.strip().lower()[:64], "login_failed", "", ip)
        session.commit()  # keeps the failure count
        raise HTTPException(401, "Wrong user name or password.")
    service.audit(session, user.username, "login", "", ip)
    _set_cookie(request, response, service.start_session(session, user))
    session.commit()
    return {"user": _public(user)}


@router.post("/auth/logout")
def logout(request: Request, response: Response, session: Session = Depends(get_session)):
    user = _current(request, session)
    service.end_session(session, _cookie(request))
    if user:
        service.audit(session, user.username, "logout", "", _ip(request))
    session.commit()
    response.delete_cookie(COOKIE, path="/")
    return {"signed_out": True}


@router.post("/auth/password")
def change_password(body: PasswordChange, request: Request, session: Session = Depends(get_session)):
    user = _current(request, session)
    if user is None:
        raise HTTPException(401, "Sign in to continue.")
    if not login_throttle.allow(f"password:{user.id}"):
        raise HTTPException(429, "Too many attempts. Wait a few minutes.")
    from app.auth import passwords
    if not passwords.verify_password(body.current_password, user.password_hash):
        raise HTTPException(403, "The current password is not right.")
    try:
        service.set_password(session, user, body.new_password)
    except service.AuthError as exc:
        raise HTTPException(422, str(exc)) from exc
    service.end_all_sessions(session, user.id, keep_token=_cookie(request))  # other devices must sign in again
    service.audit(session, user.username, "password_changed", "", _ip(request))
    session.commit()
    return {"changed": True}


# ---- administration (the guard lets only administrators in) -------------------------------------------------------
def _actor(request: Request) -> str | None:
    return (getattr(request.state, "user", None) or {}).get("username")


@router.get("/users")
def list_users(session: Session = Depends(get_session)):
    rows = session.scalars(select(UserRow).order_by(UserRow.username))
    return {"items": [u.as_dict() for u in rows], "roles": list(service.ROLES)}


@router.post("/users", status_code=201)
def create_user(body: UserCreate, request: Request, session: Session = Depends(get_session)):
    try:
        user = service.create_user(session, body.username, body.password, body.role)
    except service.AuthError as exc:
        raise HTTPException(422, str(exc)) from exc
    service.audit(session, _actor(request), "user_created", f"{user.username} as {user.role}", _ip(request))
    session.commit()
    return user.as_dict()


def _user(session: Session, user_id: int) -> UserRow:
    row = session.get(UserRow, user_id)
    if row is None:
        raise HTTPException(404, "User not found")
    return row


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserUpdate, request: Request, session: Session = Depends(get_session)):
    user, actor = _user(session, user_id), _actor(request)
    notes = []
    if body.role is not None and body.role != user.role:
        if body.role not in service.ROLES:
            raise HTTPException(422, f"The role must be one of: {', '.join(service.ROLES)}.")
        if not service.can_remove_admin(session, user):
            raise HTTPException(409, "There must always be at least one active administrator.")
        notes.append(f"role {user.role} to {body.role}")
        user.role = body.role
    if body.disabled is not None and body.disabled != user.disabled:
        if body.disabled and (user.username == actor or not service.can_remove_admin(session, user)):
            raise HTTPException(409, "You cannot disable yourself or the last active administrator.")
        user.disabled = body.disabled
        notes.append("disabled" if body.disabled else "enabled")
        if body.disabled:
            service.end_all_sessions(session, user.id)
    if body.password is not None:
        try:
            service.set_password(session, user, body.password)
        except service.AuthError as exc:
            raise HTTPException(422, str(exc)) from exc
        service.end_all_sessions(session, user.id)
        notes.append("password reset")
    if body.unlock:
        user.locked_until, user.failed_attempts = None, 0
        notes.append("unlocked")
    if notes:
        service.audit(session, actor, "user_changed", f"{user.username}: {', '.join(notes)}", _ip(request))
    session.commit()
    return user.as_dict()


@router.delete("/users/{user_id}")
def delete_user(user_id: int, request: Request, session: Session = Depends(get_session)):
    user = _user(session, user_id)
    if user.username == _actor(request) or not service.can_remove_admin(session, user):
        raise HTTPException(409, "You cannot delete yourself or the last active administrator.")
    service.end_all_sessions(session, user.id)
    session.delete(user)
    service.audit(session, _actor(request), "user_deleted", user.username, _ip(request))
    session.commit()
    return {"deleted": user_id}


@router.get("/audit")
def audit_log(limit: int = Query(100, ge=1, le=500), session: Session = Depends(get_session)):
    rows = session.scalars(select(AuditRow).order_by(AuditRow.id.desc()).limit(limit))
    return {"items": [r.as_dict() for r in rows]}
