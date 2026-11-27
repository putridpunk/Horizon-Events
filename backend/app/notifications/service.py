"""Sends new alerts to the channels the user configured, and remembers how each channel is doing."""
from __future__ import annotations

import logging
import os
import threading

from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.database.models import AlertRow
from app.database.notification_models import NotificationChannelRow
from app.domain import SEVERITY_RANK, Severity, utcnow
from app.notifications import senders

log = logging.getLogger(__name__)

MAX_ERROR = 300


def alert_text(alert: AlertRow) -> tuple[str, str, dict]:
    who = ", ".join(x for x in (alert.source_ip, alert.username) if x)
    subject = f"[{alert.severity.upper()}] {alert.rule_name}"
    lines = [alert.description or alert.rule_name]
    if who:
        lines.append(f"Source: {who}")
    lines.append(f"Occurrences: {alert.occurrences}   Alert: {alert.alert_code or alert.id}")
    data = {"alert": {"id": alert.id, "code": alert.alert_code, "rule_id": alert.rule_id, "rule_name": alert.rule_name,
                      "severity": alert.severity, "description": alert.description, "source_ip": alert.source_ip,
                      "username": alert.username, "occurrences": alert.occurrences,
                      "created_at": alert.created_at.isoformat()}}
    return subject, "\n".join(lines), data


class NotificationService:
    def __init__(self, post: senders.Post = senders.default_post,
                 smtp_factory: senders.SmtpFactory = senders.default_smtp):
        self.post, self.smtp_factory = post, smtp_factory

    def deliver(self, channel: NotificationChannelRow, subject: str, text: str, data: dict | None = None,
                attachments: list | None = None) -> None:
        """Send one message. Raises SendError; does not touch the database."""
        if channel.kind == "email":
            senders.send_email(channel.config, subject, text, attachments, self.smtp_factory)
        else:
            senders.send_http(channel.kind, channel.config, subject, text, data or {}, self.post)

    def deliver_and_record(self, channel: NotificationChannelRow, subject: str, text: str, data: dict | None = None,
                           attachments: list | None = None) -> str | None:
        """Like deliver, but stores the outcome on the channel. Returns the error text, or None on success."""
        try:
            self.deliver(channel, subject, text, data, attachments)
        except senders.SendError as exc:
            channel.last_error = str(exc)[:MAX_ERROR]
            return channel.last_error
        channel.last_error, channel.last_sent = None, utcnow()
        channel.sent_count = (channel.sent_count or 0) + 1
        return None

    def dispatch(self, session: Session, alerts: list[AlertRow]) -> int:
        """Send each alert to every enabled channel whose minimum severity it reaches. Returns messages sent."""
        channels = list(session.scalars(select(NotificationChannelRow).where(NotificationChannelRow.enabled.is_(True))))
        sent = 0
        for channel in channels:
            floor = SEVERITY_RANK[Severity(channel.min_severity)]
            for alert in alerts:
                if SEVERITY_RANK[Severity(alert.severity)] < floor:
                    continue
                if self.deliver_and_record(channel, *alert_text(alert)) is None:
                    sent += 1
        session.commit()
        return sent


_service = NotificationService()


def get_service() -> NotificationService:
    return _service


def set_service(service: NotificationService) -> None:
    global _service
    _service = service


def dispatch_async(engine: Engine, alert_ids: list[int]) -> None:
    """Notify in the background so a slow webhook never delays an import. Set HORIZON_NOTIFY_SYNC=1 to wait."""
    if not alert_ids:
        return

    def run():
        try:
            with Session(engine, expire_on_commit=False) as session:
                alerts = list(session.scalars(select(AlertRow).where(AlertRow.id.in_(alert_ids))))
                get_service().dispatch(session, alerts)
        except Exception:
            log.exception("sending notifications failed")

    if os.environ.get("HORIZON_NOTIFY_SYNC") == "1":
        run()
    else:
        threading.Thread(target=run, name="notify", daemon=True).start()
