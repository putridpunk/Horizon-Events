"""Request guard for a service that is meant to be reached from the local machine.

The API has no login, so a web page the user happens to have open must not be able to use it:

* **Host check (DNS rebinding):** an attacker domain can be made to resolve to 127.0.0.1, which would make
  the browser treat the API as same-origin and let the page read it. Real requests always carry a Host the
  attacker cannot control the DNS for, so any Host that is not a known local name is refused.
* **Origin check (cross-site request forgery):** browsers attach `Origin` to cross-site POSTs, and some
  (plain form posts, bodyless POSTs) need no CORS preflight. State-changing requests whose Origin is not a
  local name are refused. Requests without an Origin (curl, scripts) are not browser-driven and pass.

Extra hostnames (for example a reverse proxy name) can be allowed with `HORIZON_ALLOWED_HOSTS=a.example,b.example`.
"""
from __future__ import annotations

import os
from urllib.parse import urlparse

from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send

LOCAL_HOSTNAMES = frozenset({"localhost", "127.0.0.1", "::1"})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def allowed_hostnames() -> set[str]:
    extra = {h.strip().lower() for h in os.environ.get("HORIZON_ALLOWED_HOSTS", "").split(",") if h.strip()}
    return set(LOCAL_HOSTNAMES) | extra


def hostname_from_host_header(value: str) -> str:
    """'LocalHost:8080' -> 'localhost'; '[::1]:8000' -> '::1'."""
    value = value.strip().lower()
    if value.startswith("["):
        end = value.find("]")
        return value[1:end] if end != -1 else value
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def hostname_from_origin(value: str) -> str | None:
    """'http://localhost:5173' -> 'localhost'. The opaque origin 'null' (and anything unparsable) gives None."""
    try:
        hostname = urlparse(value).hostname
        return hostname.lower() if hostname else None
    except ValueError:
        return None


class LocalRequestGuard:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        allowed = allowed_hostnames()
        host = headers.get("host")
        if host is not None and hostname_from_host_header(host) not in allowed:
            await PlainTextResponse("Invalid host header", status_code=400)(scope, receive, send)
            return
        origin = headers.get("origin")
        if origin is not None and scope["method"] not in SAFE_METHODS and hostname_from_origin(origin) not in allowed:
            await PlainTextResponse("Cross-origin request blocked", status_code=403)(scope, receive, send)
            return
        await self.app(scope, receive, send)
