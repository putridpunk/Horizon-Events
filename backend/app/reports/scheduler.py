"""Reports that run by themselves: a daily or weekly report saved to the reports folder and, optionally, emailed."""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.notification_models import NotificationChannelRow, ReportScheduleRow
from app.domain import utcnow
from app.notifications.service import get_service
from app.reports.generator import FORMATS, build_report, render

log = logging.getLogger(__name__)

FREQUENCIES = {"daily": timedelta(days=1), "weekly": timedelta(days=7)}
RUN_HOUR = 7  # reports are made at 07:00 UTC, so they are ready at the start of the working day
KEEP_FILES = 30  # per schedule; older ones are deleted
MAX_ERROR = 300


class ScheduleError(ValueError):
    """A schedule that cannot be accepted; the message is shown to the user."""


def next_run_after(frequency: str, now: datetime) -> datetime:
    """The next 07:00 UTC after `now` (daily), or the next Monday at 07:00 UTC (weekly)."""
    if frequency not in FREQUENCIES:
        raise ScheduleError(f"Frequency must be one of: {', '.join(FREQUENCIES)}.")
    candidate = now.replace(hour=RUN_HOUR, minute=0, second=0, microsecond=0)
    if frequency == "weekly":
        candidate += timedelta(days=(0 - candidate.weekday()) % 7)
    while candidate <= now:
        candidate += FREQUENCIES[frequency]
    return candidate


def validate(frequency: str, fmt: str, session: Session, email_channel_id: int | None) -> None:
    if frequency not in FREQUENCIES:
        raise ScheduleError(f"Frequency must be one of: {', '.join(FREQUENCIES)}.")
    if fmt not in FORMATS:
        raise ScheduleError(f"Format must be one of: {', '.join(FORMATS)}.")
    if email_channel_id is not None:
        channel = session.get(NotificationChannelRow, email_channel_id)
        if channel is None or channel.kind != "email":
            raise ScheduleError("Choose one of your email channels, or none.")


def _prune(folder: Path, schedule_id: int) -> None:
    files = sorted(folder.glob(f"report-{schedule_id}-*"), key=lambda p: p.name)
    for old in files[:-KEEP_FILES]:
        try:
            old.unlink()
        except OSError:
            log.warning("could not delete old report %s", old)


def run_schedule(session: Session, row: ReportScheduleRow, report_dir: Path, now: datetime | None = None) -> None:
    """Make the report for the period ending now, save it, email it if asked, and plan the next run."""
    now = now or utcnow()
    start = now - FREQUENCIES[row.frequency]
    row.last_run, row.last_error = now, None
    try:
        body, mime = render(build_report(session, start, now), row.format)
        report_dir.mkdir(parents=True, exist_ok=True)
        path = report_dir / f"report-{row.id}-{now.strftime('%Y%m%d-%H%M')}.{row.format}"
        path.write_bytes(body)
        row.last_file = path.name
        _prune(report_dir, row.id)
        channel = session.get(NotificationChannelRow, row.email_channel_id) if row.email_channel_id else None
        if channel is not None:
            subject = f"Horizon Events {row.frequency} report: {row.name}"
            text = (f"Your {row.frequency} security report for {start:%Y-%m-%d %H:%M} to {now:%Y-%m-%d %H:%M} UTC "
                    "is attached.")
            error = get_service().deliver_and_record(channel, subject, text, attachments=[(path.name, body, mime)])
            if error:
                row.last_error = f"Saved, but the email failed: {error}"[:MAX_ERROR]
    except Exception as exc:  # a broken report must not stop the others or the scheduler
        log.exception("scheduled report %s failed", row.id)
        row.last_error = f"{type(exc).__name__}: {exc}"[:MAX_ERROR]
    row.next_run = next_run_after(row.frequency, now)


def run_due(session: Session, report_dir: Path, now: datetime | None = None) -> int:
    now = now or utcnow()
    due = list(session.scalars(select(ReportScheduleRow).where(
        ReportScheduleRow.enabled.is_(True), ReportScheduleRow.next_run <= now)))
    for row in due:
        run_schedule(session, row, report_dir, now)
    session.commit()
    return len(due)


class ReportScheduler:
    def __init__(self, session_factory: Callable[[], Session], report_dir: Path, interval: float = 60.0):
        self.session_factory, self.report_dir, self.interval = session_factory, report_dir, interval
        self._stop = threading.Event()

    def start(self) -> None:
        def loop():
            while not self._stop.wait(self.interval):
                try:
                    with self.session_factory() as session:
                        run_due(session, self.report_dir)
                except Exception:
                    log.exception("running scheduled reports failed")
        threading.Thread(target=loop, name="report-scheduler", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
