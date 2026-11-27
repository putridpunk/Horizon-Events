"""Scheduled reports: list, create, change, remove, run now, and download what was made."""
import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.database.notification_models import ReportScheduleRow
from app.domain import utcnow
from app.reports import scheduler
from app.reports.generator import FORMATS

router = APIRouter(prefix="/api/report-schedules", tags=["reports"])
MAX_SCHEDULES = 20


class ScheduleCreate(BaseModel):
    name: str
    frequency: str = "weekly"
    format: str = "html"
    email_channel_id: int | None = None
    enabled: bool = True


class ScheduleUpdate(BaseModel):
    name: str | None = None
    frequency: str | None = None
    format: str | None = None
    email_channel_id: int | None = None
    enabled: bool | None = None


def report_dir(request: Request | None = None) -> Path:
    configured = getattr(getattr(request, "app", None), "state", None)
    folder = getattr(configured, "report_dir", None) if configured else None
    return Path(folder or os.environ.get("HORIZON_REPORT_DIR", "reports"))


def schedule_out(row: ReportScheduleRow) -> dict:
    return {
        "id": row.id, "name": row.name, "frequency": row.frequency, "format": row.format,
        "email_channel_id": row.email_channel_id, "enabled": row.enabled, "created_at": row.created_at.isoformat(),
        "next_run": row.next_run.isoformat(), "last_run": row.last_run.isoformat() if row.last_run else None,
        "last_file": row.last_file, "last_error": row.last_error,
    }


def _name(value: str) -> str:
    name = " ".join(value.split())
    if not name or len(name) > 100:
        raise HTTPException(422, "Give the schedule a name of up to 100 characters.")
    return name


def _get(session: Session, schedule_id: int) -> ReportScheduleRow:
    row = session.get(ReportScheduleRow, schedule_id)
    if row is None:
        raise HTTPException(404, "Schedule not found")
    return row


@router.get("")
def list_schedules(session: Session = Depends(get_session)):
    rows = session.scalars(select(ReportScheduleRow).order_by(ReportScheduleRow.id))
    return {"items": [schedule_out(r) for r in rows], "frequencies": list(scheduler.FREQUENCIES),
            "formats": list(FORMATS)}


@router.post("", status_code=201)
def create_schedule(body: ScheduleCreate, session: Session = Depends(get_session)):
    if session.query(ReportScheduleRow).count() >= MAX_SCHEDULES:
        raise HTTPException(422, f"You can have at most {MAX_SCHEDULES} schedules.")
    try:
        scheduler.validate(body.frequency, body.format, session, body.email_channel_id)
    except scheduler.ScheduleError as exc:
        raise HTTPException(422, str(exc)) from exc
    now = utcnow()
    row = ReportScheduleRow(name=_name(body.name), frequency=body.frequency, format=body.format,
                            email_channel_id=body.email_channel_id, enabled=body.enabled, created_at=now,
                            next_run=scheduler.next_run_after(body.frequency, now))
    session.add(row)
    session.commit()
    return schedule_out(row)


@router.patch("/{schedule_id}")
def update_schedule(schedule_id: int, body: ScheduleUpdate, session: Session = Depends(get_session)):
    row = _get(session, schedule_id)
    fields = body.model_dump(exclude_unset=True)
    frequency, fmt = fields.get("frequency", row.frequency), fields.get("format", row.format)
    channel = fields.get("email_channel_id", row.email_channel_id)
    try:
        scheduler.validate(frequency, fmt, session, channel)
    except scheduler.ScheduleError as exc:
        raise HTTPException(422, str(exc)) from exc
    if "name" in fields and fields["name"] is not None:
        row.name = _name(fields["name"])
    if frequency != row.frequency:
        row.next_run = scheduler.next_run_after(frequency, utcnow())
    row.frequency, row.format, row.email_channel_id = frequency, fmt, channel
    if fields.get("enabled") is not None:
        row.enabled = fields["enabled"]
    session.commit()
    return schedule_out(row)


@router.delete("/{schedule_id}")
def delete_schedule(schedule_id: int, session: Session = Depends(get_session)):
    session.delete(_get(session, schedule_id))
    session.commit()
    return {"deleted": schedule_id}


@router.post("/{schedule_id}/run")
def run_now(schedule_id: int, request: Request, session: Session = Depends(get_session)):
    """Make the report now. The schedule's normal next run is moved on as if it had just run."""
    row = _get(session, schedule_id)
    scheduler.run_schedule(session, row, report_dir(request))
    session.commit()
    return schedule_out(row)


@router.get("/{schedule_id}/latest")
def download_latest(schedule_id: int, request: Request, session: Session = Depends(get_session)):
    row = _get(session, schedule_id)
    folder = report_dir(request).resolve()
    path = (folder / row.last_file).resolve() if row.last_file else None
    if path is None or folder not in path.parents or not path.is_file():
        raise HTTPException(404, "No report has been made yet")
    return FileResponse(path, media_type=FORMATS[row.format], filename=path.name)
