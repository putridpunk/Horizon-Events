"""Where new alerts are sent besides the app: webhooks, Slack, Discord and email."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.database.notification_models import NotificationChannelRow, ReportScheduleRow
from app.domain import Severity, utcnow
from app.notifications import senders
from app.notifications.service import get_service

router = APIRouter(prefix="/api/notifications", tags=["notifications"])
MAX_CHANNELS = 20


class ChannelCreate(BaseModel):
    name: str
    kind: str
    config: dict = {}
    min_severity: Severity = Severity.high
    enabled: bool = True


class ChannelUpdate(BaseModel):
    name: str | None = None
    config: dict | None = None
    min_severity: Severity | None = None
    enabled: bool | None = None


def channel_out(row: NotificationChannelRow) -> dict:
    return {
        "id": row.id, "name": row.name, "kind": row.kind, "config": senders.public_config(row.kind, row.config),
        "min_severity": row.min_severity, "enabled": row.enabled, "created_at": row.created_at.isoformat(),
        "last_sent": row.last_sent.isoformat() if row.last_sent else None, "last_error": row.last_error,
        "sent_count": row.sent_count or 0,
    }


def _name(value: str) -> str:
    name = " ".join(value.split())
    if not name or len(name) > 100:
        raise HTTPException(422, "Give the channel a name of up to 100 characters.")
    return name


def _get(session: Session, channel_id: int) -> NotificationChannelRow:
    row = session.get(NotificationChannelRow, channel_id)
    if row is None:
        raise HTTPException(404, "Channel not found")
    return row


@router.get("")
def list_channels(session: Session = Depends(get_session)):
    rows = session.scalars(select(NotificationChannelRow).order_by(NotificationChannelRow.id))
    return {"items": [channel_out(r) for r in rows], "kinds": list(senders.KINDS)}


@router.post("", status_code=201)
def create_channel(body: ChannelCreate, session: Session = Depends(get_session)):
    if session.query(NotificationChannelRow).count() >= MAX_CHANNELS:
        raise HTTPException(422, f"You can have at most {MAX_CHANNELS} channels.")
    try:
        config = senders.validate_config(body.kind, body.config)
    except senders.ChannelError as exc:
        raise HTTPException(422, str(exc)) from exc
    row = NotificationChannelRow(name=_name(body.name), kind=body.kind, config=config,
                                 min_severity=body.min_severity.value, enabled=body.enabled, created_at=utcnow())
    session.add(row)
    session.commit()
    return channel_out(row)


@router.patch("/{channel_id}")
def update_channel(channel_id: int, body: ChannelUpdate, session: Session = Depends(get_session)):
    row = _get(session, channel_id)
    if body.name is not None:
        row.name = _name(body.name)
    if body.config is not None:
        try:
            row.config = senders.validate_config(row.kind, body.config, row.config)
        except senders.ChannelError as exc:
            raise HTTPException(422, str(exc)) from exc
    if body.min_severity is not None:
        row.min_severity = body.min_severity.value
    if body.enabled is not None:
        row.enabled = body.enabled
    session.commit()
    return channel_out(row)


@router.delete("/{channel_id}")
def delete_channel(channel_id: int, session: Session = Depends(get_session)):
    row = _get(session, channel_id)
    if session.scalar(select(ReportScheduleRow.id).where(ReportScheduleRow.email_channel_id == channel_id)):
        raise HTTPException(409, "A scheduled report emails through this channel. Change or remove the schedule first.")
    session.delete(row)
    session.commit()
    return {"deleted": channel_id}


@router.post("/{channel_id}/test")
def test_channel(channel_id: int, session: Session = Depends(get_session)):
    """Send a test message and report whether it arrived, so a wrong address shows up straight away."""
    row = _get(session, channel_id)
    error = get_service().deliver_and_record(
        row, "Horizon Events test", "This is a test message from Horizon Events. Your channel works.",
        {"test": True})
    session.commit()
    return {"ok": error is None, "error": error, "channel": channel_out(row)}
