"""Is there a newer release? Asks GitHub's public release list and compares version numbers. It never downloads or installs
anything: it shows the release page, and the user decides.

The request carries no data from this installation (only a fixed program name), but GitHub can see the address it comes
from, so automatic checks are off until the user turns them on."""
from __future__ import annotations

import json
import logging
import re
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from typing import Callable

from sqlalchemy.orm import Session

from app.database.collector_models import get_setting, set_setting
from app.domain import utcnow
from app.version import __version__

RELEASE_API = "https://api.github.com/repos/putridpunk/Horizon-Events/releases/latest"
RELEASE_PAGE_PREFIX = "https://github.com/putridpunk/Horizon-Events/"
AUTO_KEY, LAST_KEY = "update_auto", "update_last"
AUTO_EVERY = timedelta(hours=24)
MAX_BYTES = 1_000_000
MAX_NOTES = 2000
_TAG = re.compile(r"^v?(\d{1,4})\.(\d{1,4})\.(\d{1,4})$")

Fetch = Callable[[str], dict]


class UpdateError(RuntimeError):
    """The check could not be completed; the message is shown to the user."""


def parse_version(text: str | None) -> tuple[int, int, int] | None:
    """`v1.5.0` or `1.5.0`. Anything else (a pre-release such as 1.5.0-rc1, a name) is not a version we compare."""
    m = _TAG.match((text or "").strip())
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def http_get_json(url: str) -> dict:
    if not url.startswith("https://api.github.com/"):
        raise UpdateError("Only GitHub's release list can be asked.")
    request = urllib.request.Request(url, headers={"User-Agent": "HorizonEvents", "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 (https only, fixed host)
            data = response.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise UpdateError("GitHub answered with an error (" + str(exc.code) + "). Try again later.") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise UpdateError("Could not reach GitHub. Check the internet connection.") from exc
    if len(data) > MAX_BYTES:
        raise UpdateError("GitHub's answer was larger than expected.")
    try:
        parsed = json.loads(data)
    except ValueError:
        raise UpdateError("GitHub's answer could not be read.") from None
    if not isinstance(parsed, dict):
        raise UpdateError("GitHub's answer could not be read.")
    return parsed


def _load(session: Session) -> dict:
    try:
        value = json.loads(get_setting(session, LAST_KEY, "{}") or "{}")
        return value if isinstance(value, dict) else {}
    except ValueError:
        return {}


def auto_enabled(session: Session) -> bool:
    return get_setting(session, AUTO_KEY, "false") == "true"


def set_auto(session: Session, on: bool) -> None:
    set_setting(session, AUTO_KEY, "true" if on else "false")


def check(session: Session, fetch: Fetch | None = None, now: datetime | None = None) -> dict:
    """Ask for the latest release and remember the answer. Never raises: a failure is recorded as `error`."""
    now = now or utcnow()
    result: dict = {"checked_at": now.isoformat(), "error": None}
    try:
        release = (fetch or http_get_json)(RELEASE_API)
        tag = str(release.get("tag_name") or "")
        if parse_version(tag) is None:
            raise UpdateError("The latest release has a name that cannot be compared with this version.")
        page = str(release.get("html_url") or "")
        result.update(latest=tag.lstrip("v"), url=page if page.startswith(RELEASE_PAGE_PREFIX) else RELEASE_PAGE_PREFIX + "releases/latest",
                      notes=" ".join(str(release.get("body") or "").split())[:MAX_NOTES],
                      published=str(release.get("published_at") or "")[:25] or None)
    except UpdateError as exc:
        result["error"] = str(exc)
        previous = _load(session)  # keep what we knew
        result.update({k: previous[k] for k in ("latest", "url", "notes", "published") if k in previous})
    set_setting(session, LAST_KEY, json.dumps(result))
    session.commit()
    return status(session)


def status(session: Session) -> dict:
    last = _load(session)
    latest = last.get("latest")
    newer = bool(latest and parse_version(latest) and parse_version(latest) > parse_version(__version__))
    return {"current": __version__, "auto_check": auto_enabled(session), "checked_at": last.get("checked_at"),
            "latest": latest, "update_available": newer, "url": last.get("url") if newer else None,
            "notes": last.get("notes") if newer else None, "published": last.get("published"), "error": last.get("error")}


def maybe_auto_check(session: Session, fetch: Fetch | None = None, now: datetime | None = None) -> bool:
    """Check when automatic checks are on and the last one is more than a day old. Returns True if it asked."""
    now = now or utcnow()
    if not auto_enabled(session):
        return False
    when = _load(session).get("checked_at")
    try:
        if when and now - datetime.fromisoformat(when) < AUTO_EVERY:
            return False
    except ValueError:
        pass
    check(session, fetch, now)
    return True


class AutoChecker:
    """Once a minute after start, then every few hours, checks if the user switched automatic checks on."""

    def __init__(self, session_factory: Callable[[], Session], interval: float = 6 * 3600, first_delay: float = 60.0):
        self.session_factory, self.interval, self.first_delay = session_factory, interval, first_delay
        self._stop = threading.Event()

    def start(self) -> None:
        def loop():
            wait = self.first_delay
            while not self._stop.wait(wait):
                try:
                    with self.session_factory() as session:
                        maybe_auto_check(session)
                except Exception:
                    logging.getLogger(__name__).exception("the automatic update check failed")
                wait = self.interval
        threading.Thread(target=loop, name="update-check", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
