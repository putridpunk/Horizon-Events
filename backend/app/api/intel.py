from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.intel import service as intel

router = APIRouter(prefix="/api/intel", tags=["intel"])


class RefreshRequest(BaseModel):
    feeds: list[str] | None = None


@router.get("/status")
def status(session: Session = Depends(get_session)):
    return {"feeds": intel.feed_status(session), "min_refresh_minutes": 60}


@router.post("/refresh")
def refresh(body: RefreshRequest | None = None, session: Session = Depends(get_session)):
    """Downloads the requested feeds from their public sources. No log data is sent."""
    try:
        results = intel.refresh_feeds(session, body.feeds if body else None, fetch=lambda url: intel.http_fetch(url))
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    return {"results": results, "feeds": intel.feed_status(session)}
