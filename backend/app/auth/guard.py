"""Who may call what. A pure ASGI middleware that, when sign-in is on, checks the session cookie before any API request
reaches its handler: no handler can forget to check.

Roles: viewer (read everything but settings), analyst (also work alerts and incidents, import logs, save searches),
admin (everything, including users, rules, notifications, data and anything that changes this computer)."""
from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from http.cookies import CookieError, SimpleCookie
from typing import Callable

from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.auth import service
from app.database.connection import get_engine

COOKIE = "horizon_session"
MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
DOC_PATHS = frozenset({"/docs", "/redoc", "/openapi.json"})

# First match wins. None as the methods means every method. Anything not listed: read = viewer, change = admin.
RULES: list[tuple[frozenset | None, re.Pattern, str]] = [
    (None, re.compile(r"^/api/(users|audit|notifications)(/|$)"), "admin"),
    (None, re.compile(r"^/api/(data|desktop|geoip|update)(/|$)"), "admin"),
    (frozenset({"POST"}), re.compile(r"^/api/rules/replay$"), "analyst"),
    (MUTATING, re.compile(r"^/api/(alerts|incidents|searches|suppressions)(/|$)"), "analyst"),
    (frozenset({"POST"}), re.compile(r"^/api/imports$"), "analyst"),
]
PUBLIC = {("GET", "/api/health"), ("GET", "/api/auth/status"), ("POST", "/api/auth/login"), ("POST", "/api/auth/setup")}


def required_role(method: str, path: str) -> str | None:
    """The lowest role allowed, or None when anyone may call it."""
    path = path.rstrip("/") or "/"
    if (method, path) in PUBLIC:
        return None
    if path.startswith("/api/auth/") or path in DOC_PATHS:
        return "viewer"
    for methods, pattern, role in RULES:
        if (methods is None or method in methods) and pattern.match(path):
            return role
    return "admin" if method in MUTATING else "viewer"


def _default_factory() -> Session:
    return Session(get_engine(), expire_on_commit=False)


_factory: Callable[[], Session] = _default_factory


def set_session_factory(factory: Callable[[], Session] | None) -> None:
    """Tests point the guard at their own database."""
    global _factory
    _factory = factory or _default_factory


def cookie_value(headers: dict) -> str | None:
    try:
        morsel = SimpleCookie(headers.get("cookie", "")).get(COOKIE)
    except CookieError:
        return None
    return morsel.value if morsel else None


def _who(token: str | None) -> dict | None:
    with _factory() as session:
        user = service.resolve_session(session, token)
        session.commit()  # remembers activity, and removes an expired session
        return {"id": user.id, "username": user.username, "role": user.role} if user else None


class AuthGuard:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not service.enabled():
            await self.app(scope, receive, send)
            return
        path = scope["path"]
        if not (path.startswith("/api") or path in DOC_PATHS):  # the web page itself holds no data
            await self.app(scope, receive, send)
            return
        needed = required_role(scope["method"], path)
        if needed is None:
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        who = await run_in_threadpool(_who, cookie_value(headers))
        if who is None:
            await JSONResponse({"detail": "Sign in to continue."}, status_code=401)(scope, receive, send)
            return
        if service.RANK[who["role"]] < service.RANK[needed]:
            await JSONResponse({"detail": f"Your role ({who['role']}) is not allowed to do this. It needs {needed}."},
                               status_code=403)(scope, receive, send)
            return
        scope.setdefault("state", {})["user"] = who
        await self.app(scope, receive, send)


class LoginThrottle:
    """At most `limit` sign-in attempts per address in `window` seconds, on top of the per-account lock-out."""

    def __init__(self, limit: int = 20, window: float = 600.0, clock: Callable[[], float] = time.monotonic):
        self.limit, self.window, self.clock = limit, window, clock
        self._hits: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now, hits = self.clock(), self._hits[key]
        while hits and now - hits[0] > self.window:
            hits.popleft()
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        if len(self._hits) > 5000:  # forget addresses that have been quiet
            for k in [k for k, v in self._hits.items() if not v or now - v[-1] > self.window]:
                del self._hits[k]
        return True

    def reset(self) -> None:
        self._hits.clear()


login_throttle = LoginThrottle()
