"""Helpers for the desktop build: a per-launch session secret, a free port, a single-instance lock.

The desktop app serves its UI on 127.0.0.1 and shows it in a native window. So that nothing else (another
browser tab, another program) can use that server, every request must carry a random per-launch secret.
The window receives it once as `?hz=<secret>`; the guard turns that into an HttpOnly cookie and redirects to
the same address without the secret. Without the cookie everything answers 401.
"""
from __future__ import annotations

import hmac
import os
import secrets
import socket
import sys
import time
import urllib.error
import urllib.request
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from urllib.parse import parse_qsl, urlencode

from starlette.responses import PlainTextResponse, RedirectResponse
from starlette.types import ASGIApp, Receive, Scope, Send

COOKIE_NAME = "hz_session"
BOOTSTRAP_PARAM = "hz"


def make_secret() -> str:
    return secrets.token_urlsafe(32)


def pick_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def remembered_port(path) -> int:
    """The port the window's address uses. The browser engine keeps saved settings (language, overview layout) per
    address, and the port is part of the address, so a new random port on every launch made the window forget them.
    The last port is kept in a small file and used again when it is free; otherwise a new free one is chosen."""
    path = Path(path)
    try:
        saved = int(path.read_text(encoding="ascii").strip())
        if 1024 <= saved <= 65535:
            with socket.socket() as s:
                s.bind(("127.0.0.1", saved))
            return saved
    except (OSError, ValueError):
        pass
    port = pick_free_port()
    try:
        path.write_text(str(port), encoding="ascii")
    except OSError:
        pass  # without the file the app still works; it just forgets its settings
    return port


def _same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


class SessionGuard:
    """Requires the per-launch secret (as a cookie) on every request. Inactive when the secret is unset."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        secret = os.environ.get("HORIZON_SESSION_SECRET")
        if scope["type"] != "http" or not secret:
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        try:
            cookie = SimpleCookie(headers.get("cookie", "")).get(COOKIE_NAME)
        except CookieError:
            cookie = None
        if cookie is not None and _same(cookie.value, secret):
            await self.app(scope, receive, send)
            return
        params = parse_qsl(scope.get("query_string", b"").decode("latin-1"), keep_blank_values=True)
        supplied = next((v for k, v in params if k == BOOTSTRAP_PARAM), None)
        if supplied is not None and _same(supplied, secret):
            rest = [(k, v) for k, v in params if k != BOOTSTRAP_PARAM]
            target = scope.get("root_path", "") + scope["path"] + (f"?{urlencode(rest)}" if rest else "")
            response = RedirectResponse(target, status_code=302)
            response.set_cookie(COOKIE_NAME, secret, httponly=True, samesite="strict", path="/")
            await response(scope, receive, send)
            return
        await PlainTextResponse("Unauthorized", status_code=401)(scope, receive, send)


class SingleInstance:
    """A lock file held for the life of the process. The OS releases it if the process dies."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._handle = None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(self.path, "a+b")
        try:
            if handle.tell() == 0 and self.path.stat().st_size == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            if sys.platform == "win32":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            return False
        self._handle = handle
        return True

    def release(self) -> None:
        handle, self._handle = self._handle, None
        if handle is None:
            return
        try:
            handle.seek(0)
            if sys.platform == "win32":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            handle.close()


def wait_until_ready(url: str, timeout: float = 15) -> bool:
    """True once the server answers with any HTTP response (even 401), False after `timeout` seconds."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1).close()
            return True
        except urllib.error.HTTPError:
            return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.1)
    return False
