from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.services import statistics as st

router = APIRouter(prefix="/api/statistics", tags=["statistics"])


@router.get("/overview")
def overview(session: Session = Depends(get_session)):
    return st.overview(session)


@router.get("/timeseries")
def timeseries(bucket: str = "hour", start: datetime | None = None, end: datetime | None = None,
               session: Session = Depends(get_session)):
    try:
        return st.events_over_time(session, bucket, start, end)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@router.get("/event-types")
def event_types(limit: int = Query(10, ge=1, le=50), session: Session = Depends(get_session)):
    return st.top_event_types(session, limit)


@router.get("/source-ips")
def source_ips(limit: int = Query(10, ge=1, le=50), session: Session = Depends(get_session)):
    return st.top_source_ips(session, limit)


@router.get("/severity")
def severity(session: Session = Depends(get_session)):
    return st.alert_severity_distribution(session)


@router.get("/rules")
def rules(session: Session = Depends(get_session)):
    return st.rule_stats(session)
