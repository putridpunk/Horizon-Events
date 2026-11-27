"""Remembering which location database to use."""
from __future__ import annotations

import logging
import os

from sqlalchemy.orm import Session

from app.database.collector_models import get_setting, set_setting
from app.geo.locator import GeoError, GeoLocator, get_locator, set_locator

log = logging.getLogger(__name__)
KEY = "geoip_path"
ENV = "HORIZON_GEOIP_DB"


def stored_path(session: Session) -> str:
    return get_setting(session, KEY, "")


def configure(session: Session, path: str | None) -> GeoLocator | None:
    """Use (and remember) the database at `path`; None switches location rules off. Raises GeoError."""
    if not path or not path.strip():
        set_setting(session, KEY, "")
        session.commit()
        set_locator(None)
        return None
    locator = GeoLocator.open(path.strip())  # raises GeoError before anything is changed
    set_setting(session, KEY, path.strip())
    session.commit()
    set_locator(locator)
    return locator


def load_on_start(session: Session) -> str | None:
    """Open the configured database at start-up. Returns an error message, or None. Never raises."""
    path = os.environ.get(ENV, "").strip() or stored_path(session)
    if not path:
        return None
    try:
        set_locator(GeoLocator.open(path))
        return None
    except GeoError as exc:
        log.warning("location database not loaded: %s", exc)
        return str(exc)


def status(session: Session, error: str | None = None) -> dict:
    locator = get_locator()
    return {"configured": locator is not None, "path": stored_path(session) or os.environ.get(ENV) or None,
            "database": locator.info if locator else None, "error": error,
            "from_environment": bool(os.environ.get(ENV, "").strip())}
