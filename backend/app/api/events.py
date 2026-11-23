from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.schemas import event_out
from app.database.connection import get_session
from app.database.repositories import EventRepository
from app.intel.service import enrich

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("")
def list_events(q: str | None = None, source: str | None = None, event_type: str | None = None,
                severity: str | None = None, start: datetime | None = None, end: datetime | None = None,
                limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
                session: Session = Depends(get_session)):
    rows, total = EventRepository(session).search(q, source, event_type, severity, start, end, limit, offset)
    return {"items": [event_out(r) for r in rows], "total": total}


@router.get("/{event_id}")
def get_event(event_id: int, session: Session = Depends(get_session)):
    row = EventRepository(session).get(event_id)
    if row is None:
        raise HTTPException(404, "Event not found")
    return {**event_out(row), "intel": enrich(session, row.source_ip)}
