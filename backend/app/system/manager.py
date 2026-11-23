"""Runs the collectors on a background thread and reports their state."""
from __future__ import annotations

import threading
import time
from typing import Callable

from sqlalchemy.orm import Session

from app.database.collector_models import CollectorSettingRow
from app.domain import utcnow
from app.system.base import READY, Collector


class CollectorManager:
    def __init__(self, collectors: list[Collector], session_factory: Callable[[], Session],
                 interval: float = 5.0, access_ttl: float = 30.0):
        self.collectors = {c.id: c for c in collectors}
        self.session_factory = session_factory
        self.interval = interval
        self.access_ttl = access_ttl
        self._access_cache: dict[str, tuple[float, str]] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._paused = False

    # -- state ------------------------------------------------------------------------------
    def _access(self, collector: Collector, fresh: bool = False) -> str:
        now = time.monotonic()
        with self._lock:
            cached = self._access_cache.get(collector.id)
        if not fresh and cached and now - cached[0] < self.access_ttl:
            return cached[1]
        try:
            state = collector.access()
        except Exception:  # access() must not raise, but a bug here must not stop the others
            state = "unavailable"
        with self._lock:
            self._access_cache[collector.id] = (now, state)
        return state

    def _setting(self, session: Session, collector_id: str) -> CollectorSettingRow:
        row = session.get(CollectorSettingRow, collector_id)
        if row is None:
            row = CollectorSettingRow(id=collector_id)
            session.add(row)
            session.flush()
        return row

    def _entry(self, collector: Collector, row: CollectorSettingRow, fresh: bool = False) -> dict:
        access = self._access(collector, fresh)
        state = "off" if not row.enabled else ("collecting" if access == READY else access)
        return {
            "id": collector.id, "name": collector.name, "description": collector.description,
            "platform": collector.platform, "enabled": bool(row.enabled), "access": access, "state": state,
            "events_read": row.events_read or 0,
            "last_activity": row.last_activity.isoformat() if row.last_activity else None,
            "last_error": row.last_error,
        }

    def status(self) -> list[dict]:
        with self.session_factory() as session:
            entries = [self._entry(c, self._setting(session, c.id)) for c in self.collectors.values()]
            session.commit()
        return entries

    # -- actions ----------------------------------------------------------------------------
    def set_enabled(self, collector_id: str, enabled: bool, backfill_hours: int | None = None) -> dict:
        collector = self.collectors[collector_id]  # KeyError for an unknown id; the API turns it into 404
        with self.session_factory() as session:
            row = self._setting(session, collector_id)
            row.enabled = enabled
            if enabled and backfill_hours is not None:
                row.backfill_hours = backfill_hours
            if not enabled:
                row.last_error = None
            session.commit()
            return self._entry(collector, row)

    def check(self, collector_id: str) -> dict:
        collector = self.collectors[collector_id]
        with self.session_factory() as session:
            row = self._setting(session, collector_id)
            entry = self._entry(collector, row, fresh=True)
            session.commit()
            return entry

    def poll_once(self) -> int:
        """Poll every enabled, readable collector once. Failures are recorded, never raised."""
        if self._paused:
            return 0
        total = 0
        for collector in self.collectors.values():
            with self.session_factory() as session:
                row = self._setting(session, collector.id)
                enabled = bool(row.enabled)
                session.commit()
            if not enabled or self._access(collector) != READY:
                continue
            total += self._poll_one(collector)
        return total

    def _poll_one(self, collector: Collector) -> int:
        error = ""
        with self.session_factory() as session:
            row = self._setting(session, collector.id)
            try:
                imported = collector.poll(session, row)
                row.events_read = (row.events_read or 0) + imported
                if imported:
                    row.last_activity = utcnow()
                row.last_error = None
                session.commit()
                return imported
            except Exception as exc:
                session.rollback()
                error = f"{type(exc).__name__}: {exc}"[:500]
        with self.session_factory() as session:  # record the failure in a clean transaction
            row = self._setting(session, collector.id)
            row.last_error = error
            session.commit()
        return 0

    # -- lifecycle --------------------------------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="horizon-collectors", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:
                pass
            self._stop.wait(self.interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def pause(self) -> None:
        self._paused = True

    def resume(self) -> None:
        self._paused = False

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())
