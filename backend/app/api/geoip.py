"""The location database used by the sign-in location rules (see app/geo)."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.geo import settings
from app.geo.locator import GeoError

router = APIRouter(prefix="/api/geoip", tags=["geoip"])


class GeoIpUpdate(BaseModel):
    path: str | None = None


@router.get("")
def get_status(request: Request, session: Session = Depends(get_session)):
    return settings.status(session, getattr(request.app.state, "geo_error", None))


@router.put("")
def set_database(body: GeoIpUpdate, request: Request, session: Session = Depends(get_session)):
    """Choose the database file (an absolute path ending in .mmdb), or send `null` to switch locations off."""
    try:
        settings.configure(session, body.path)
    except GeoError as exc:
        raise HTTPException(422, str(exc)) from exc
    request.app.state.geo_error = None
    return settings.status(session)
