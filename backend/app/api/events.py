import csv
import io
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.schemas import event_out
from app.database.connection import get_session
from app.database.repositories import EventRepository
from app.database.search_models import SavedSearchRow
from app.domain import utcnow
from app.intel.service import enrich
from app.search.query import FIELD_NAMES, SearchError, compile_query

router = APIRouter(prefix="/api/events", tags=["events"])
searches = APIRouter(prefix="/api/searches", tags=["events"])

EXPORT_MAX = 50_000
MAX_SAVED = 50
EXPORT_COLUMNS = ["id", "timestamp", "source", "event_type", "severity", "username", "source_ip", "host", "service",
                  "message"]


def _search(repo: EventRepository, **kwargs):
    try:
        return repo.search(**kwargs)
    except SearchError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("")
def list_events(q: str | None = None, query: str | None = None, source: str | None = None,
                event_type: str | None = None, severity: str | None = None, start: datetime | None = None,
                end: datetime | None = None, limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
                session: Session = Depends(get_session)):
    """`query` is the search language (see the Events page); `q` is a plain text search kept for older callers."""
    rows, total = _search(EventRepository(session), q=q, source=source, event_type=event_type, severity=severity,
                          start=start, end=end, limit=limit, offset=offset, query=query)
    return {"items": [event_out(r) for r in rows], "total": total}


def _csv_cell(value) -> str:
    """Spreadsheets run text that starts with = + - @ as a formula; a leading quote makes it plain text."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


@router.get("/export")
def export_events(format: str = "csv", q: str | None = None, query: str | None = None, source: str | None = None,
                  event_type: str | None = None, severity: str | None = None, start: datetime | None = None,
                  end: datetime | None = None, limit: int = Query(10_000, ge=1, le=EXPORT_MAX),
                  session: Session = Depends(get_session)):
    """Download the events a search matches (newest first, at most `limit`) as CSV or JSON."""
    if format not in ("csv", "json"):
        raise HTTPException(422, "format must be csv or json")
    rows, total = _search(EventRepository(session), q=q, source=source, event_type=event_type, severity=severity,
                          start=start, end=end, limit=limit, offset=0, query=query)
    items = [event_out(r) for r in rows]
    if format == "json":
        body = json.dumps({"total": total, "exported": len(items), "items": items}, indent=2)
        media = "application/json"
    else:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(EXPORT_COLUMNS)
        for item in items:
            writer.writerow([_csv_cell(item[c]) for c in EXPORT_COLUMNS])
        body, media = buf.getvalue(), "text/csv"
    return Response(body.encode("utf-8"), media_type=media, headers={
        "Content-Disposition": f'attachment; filename="horizon-events.{format}"', "X-Total-Matches": str(total)})


@router.get("/{event_id}")
def get_event(event_id: int, session: Session = Depends(get_session)):
    row = EventRepository(session).get(event_id)
    if row is None:
        raise HTTPException(404, "Event not found")
    return {**event_out(row), "intel": enrich(session, row.source_ip)}


# ---- saved searches --------------------------------------------------------------------------------------------
class SavedSearchCreate(BaseModel):
    name: str
    query: str


@searches.get("")
def list_saved(session: Session = Depends(get_session)):
    rows = session.scalars(select(SavedSearchRow).order_by(SavedSearchRow.name))
    return {"items": [r.as_dict() for r in rows], "fields": FIELD_NAMES}


@searches.post("", status_code=201)
def save_search(body: SavedSearchCreate, session: Session = Depends(get_session)):
    name, text = " ".join(body.name.split()), body.query.strip()
    if not name or len(name) > 100:
        raise HTTPException(422, "Give the search a name of up to 100 characters.")
    if not text:
        raise HTTPException(422, "There is no search to save.")
    try:
        compile_query(text)
    except SearchError as exc:
        raise HTTPException(422, str(exc)) from exc
    existing = [r.name.lower() for r in session.scalars(select(SavedSearchRow))]
    if name.lower() in existing:
        raise HTTPException(422, "A saved search with this name already exists.")
    if len(existing) >= MAX_SAVED:
        raise HTTPException(422, f"You can save at most {MAX_SAVED} searches.")
    row = SavedSearchRow(name=name, query=text, created_at=utcnow())
    session.add(row)
    session.commit()
    return row.as_dict()


@searches.delete("/{search_id}")
def delete_saved(search_id: int, session: Session = Depends(get_session)):
    row = session.get(SavedSearchRow, search_id)
    if row is None:
        raise HTTPException(404, "Saved search not found")
    session.delete(row)
    session.commit()
    return {"deleted": search_id}
