"""Tell the user about new alerts through a Windows notification. Only alerts raised after the app started."""
from __future__ import annotations

import logging
import threading
from typing import Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database.models import AlertRow
from app.shell.settings import load

log = logging.getLogger(__name__)

LEVELS = {"critical": ("critical",), "high": ("critical", "high")}
MAX_INDIVIDUAL = 3


def describe(alert: AlertRow) -> str:
    who = " ".join(x for x in (alert.source_ip, alert.username) if x)
    return f"{alert.rule_name}" + (f" ({who})" if who else "")


class AlertNotifier:
    def __init__(self, session_factory: Callable[[], Session], notify: Callable[[str, str], None], interval: float = 10.0):
        self.session_factory, self.notify, self.interval = session_factory, notify, interval
        with session_factory() as session:
            self.last_id = session.scalar(select(func.max(AlertRow.id))) or 0
        self._stop = threading.Event()

    def tick(self) -> int:
        """Look for alerts newer than the last one seen. Returns how many were announced."""
        with self.session_factory() as session:
            level = load(session)["notify"]
            rows = list(session.scalars(select(AlertRow).where(AlertRow.id > self.last_id).order_by(AlertRow.id)))
        if not rows:
            return 0
        self.last_id = rows[-1].id
        wanted = [r for r in rows if r.severity in LEVELS.get(level, ()) and r.status == "OPEN"]
        if not wanted:
            return 0
        top = "Critical alert" if any(r.severity == "critical" for r in wanted) else "High alert"
        shown = wanted[:MAX_INDIVIDUAL]
        lines = [describe(r) for r in shown]
        if len(wanted) > len(shown):
            lines.append(f"and {len(wanted) - len(shown)} more")
        self.notify(f"Horizon Events: {top}" if len(wanted) == 1 else f"Horizon Events: {len(wanted)} new alerts",
                    "\n".join(lines))
        return len(wanted)

    def start(self) -> None:
        def loop():
            while not self._stop.wait(self.interval):
                try:
                    self.tick()
                except Exception:
                    log.exception("checking for new alerts failed")
        threading.Thread(target=loop, name="alert-notifier", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
