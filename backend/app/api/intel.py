from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.intel import ioc
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


@router.post("/import", status_code=201)
async def import_list(name: str = Form(...), file: UploadFile = File(...), session: Session = Depends(get_session)):
    """Add a list of bad IP addresses, file hashes and domains from a STIX 2.1, MISP or plain-text file.
    Nothing is downloaded; matching stays on this computer. A list with the same name is replaced."""
    data = await file.read(intel.MAX_BYTES + 1)
    if len(data) > intel.MAX_BYTES:
        raise HTTPException(413, "The file is larger than 10 MB.")
    try:
        result = ioc.import_list(session, name, data.decode("utf-8", errors="replace"))
    except ioc.IocError as exc:
        raise HTTPException(422, str(exc)) from exc
    return {**result, "feeds": intel.feed_status(session)}


@router.delete("/feeds/{feed_id}")
def delete_list(feed_id: str, session: Session = Depends(get_session)):
    try:
        removed = ioc.delete_list(session, feed_id)
    except ioc.IocError as exc:
        raise HTTPException(422, str(exc)) from exc
    if not removed:
        raise HTTPException(404, "List not found")
    return {"deleted": feed_id, "feeds": intel.feed_status(session)}
