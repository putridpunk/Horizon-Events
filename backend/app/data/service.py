"""Keeping the database in check: age-based clean-up of old events, and backup and restore of the built-in
(SQLite) database. Restoring is staged and applied at the next start, because the running app has the file open."""
from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
import threading
from datetime import timedelta
from pathlib import Path

from sqlalchemy import delete, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.database.collector_models import get_setting, set_setting
from app.database.models import AlertEventLink, EventRow
from app.domain import utcnow

log = logging.getLogger(__name__)

SETTING_KEY = "retention"
MAX_DAYS = 3650
SQLITE_HEADER = b"SQLite format 3\x00"
BACKUP_SUFFIX = ".hzbackup"
PENDING = "restore.pending"
REQUIRED_TABLES = {"events", "alerts", "detection_rules"}


class DataError(ValueError):
    """A request that cannot be carried out; the message is shown to the user."""


# ---- retention -------------------------------------------------------------------------------------------------
def get_retention_days(session: Session) -> int:
    try:
        return int(json.loads(get_setting(session, SETTING_KEY, "{}") or "{}").get("days", 0))
    except (ValueError, TypeError, AttributeError):
        return 0


def set_retention_days(session: Session, days) -> int:
    if not isinstance(days, int) or isinstance(days, bool) or not 0 <= days <= MAX_DAYS:
        raise DataError(f"Keep events for 0 (forever) to {MAX_DAYS} days.")
    set_setting(session, SETTING_KEY, json.dumps({"days": days}))
    return days


def purge_old_events(session: Session, days: int) -> int:
    """Delete events older than `days` days that no alert refers to. Returns how many were deleted."""
    if days <= 0:
        return 0
    cutoff = utcnow() - timedelta(days=days)
    linked = select(AlertEventLink.event_id)
    result = session.execute(delete(EventRow).where(EventRow.timestamp < cutoff, EventRow.id.not_in(linked)))
    session.flush()
    return result.rowcount or 0


# ---- backup and restore ----------------------------------------------------------------------------------------
def _is_sqlite_file(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(len(SQLITE_HEADER)) == SQLITE_HEADER
    except OSError:
        return False


def _tables(path: Path) -> set[str]:
    con = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        return {r[0] for r in con.execute("select name from sqlite_master where type='table'")}
    finally:
        con.close()


def _absolute(path: str, what: str) -> Path:
    p = Path(path) if isinstance(path, str) else None
    if p is None or not path.strip() or "\x00" in path or not p.is_absolute() or str(path).startswith(("\\\\", "//")):
        raise DataError(f"Choose a file on this computer for the {what}.")
    return p


class DataService:
    def __init__(self, session_factory, engine: Engine, data_dir: Path | None = None):
        self.session_factory, self.engine = session_factory, engine
        self.data_dir = Path(data_dir) if data_dir else None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -- status / retention ----------------------------------------------------------------------------------
    @property
    def backups_available(self) -> bool:
        return self.data_dir is not None and self.engine.url.get_backend_name() == "sqlite" and bool(self.engine.url.database)

    def status(self) -> dict:
        with self.session_factory() as session:
            events = session.scalar(select(func.count(EventRow.id))) or 0
            oldest = session.scalar(select(func.min(EventRow.timestamp)))
            days = get_retention_days(session)
        size = None
        if self.backups_available:
            try:
                size = os.path.getsize(self.engine.url.database)
            except OSError:
                pass
        pending = bool(self.data_dir and (self.data_dir / PENDING).exists())
        return {"backups_available": self.backups_available, "retention_days": days, "events": events,
                "oldest_event": oldest.isoformat() if oldest else None, "database_bytes": size,
                "restore_pending": pending}

    def set_retention(self, days) -> int:
        with self.session_factory() as session:
            value = set_retention_days(session, days)
            session.commit()
            return value

    def purge(self) -> int:
        with self.session_factory() as session:
            removed = purge_old_events(session, get_retention_days(session))
            session.commit()
            return removed

    def start(self, interval_seconds: float = 3600.0) -> None:
        def loop():
            while not self._stop.wait(interval_seconds):
                try:
                    removed = self.purge()
                    if removed:
                        log.info("retention removed %s old events", removed)
                except Exception:
                    log.exception("retention clean-up failed")
        self._thread = threading.Thread(target=loop, name="retention", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    # -- backup / restore ------------------------------------------------------------------------------------
    def _require_backups(self) -> None:
        if not self.backups_available:
            raise DataError("Backups are only available for the built-in database in the desktop app.")

    def backup(self, destination: str) -> dict:
        self._require_backups()
        dest = _absolute(destination, "backup")
        if dest.suffix.lower() != BACKUP_SUFFIX:
            raise DataError(f"A backup file must end in {BACKUP_SUFFIX}.")
        if dest.is_dir() or not dest.parent.is_dir():
            raise DataError("The backup location does not exist.")
        if dest.exists() and not _is_sqlite_file(dest):
            raise DataError("A different kind of file is already there; it was not overwritten.")
        source = sqlite3.connect(self.engine.url.database)
        target = sqlite3.connect(str(dest))
        try:
            source.backup(target)  # a consistent copy, even while the app is writing
        finally:
            target.close()
            source.close()
        return {"path": str(dest), "bytes": dest.stat().st_size}

    def stage_restore(self, source: str) -> dict:
        self._require_backups()
        src = _absolute(source, "restore")
        if not src.is_file() or not _is_sqlite_file(src):
            raise DataError("That file is not a Horizon Events backup.")
        try:
            missing = REQUIRED_TABLES - _tables(src)
        except sqlite3.Error as exc:
            raise DataError("That file is not a readable Horizon Events backup.") from exc
        if missing:
            raise DataError("That file is not a Horizon Events backup.")
        shutil.copyfile(src, self.data_dir / PENDING)
        return {"restart_required": True}

    def cancel_restore(self) -> None:
        if self.data_dir:
            (self.data_dir / PENDING).unlink(missing_ok=True)


def apply_pending_restore(data_dir: Path, database_file: Path) -> bool:
    """Run before the database is opened. Swaps in a staged backup, keeping the previous database next to it."""
    pending = Path(data_dir) / PENDING
    if not pending.exists():
        return False
    try:
        if not _is_sqlite_file(pending) or REQUIRED_TABLES - _tables(pending):
            raise DataError("staged restore is not a valid backup")
        for suffix in ("-wal", "-shm", "-journal"):
            Path(str(database_file) + suffix).unlink(missing_ok=True)
        if database_file.exists():
            shutil.move(str(database_file), str(database_file) + ".before-restore")
        shutil.move(str(pending), str(database_file))
        return True
    except (OSError, DataError, sqlite3.Error):
        log.exception("could not apply the staged restore; keeping the current database")
        pending.unlink(missing_ok=True)
        return False
