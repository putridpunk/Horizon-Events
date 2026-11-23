"""The collector interface. A collector knows how to read one system log source."""
from __future__ import annotations

from abc import ABC, abstractmethod

from sqlalchemy.orm import Session

from app.database.collector_models import CollectorSettingRow

# What a collector can report about whether it may read its source right now.
READY = "ready"
NEEDS_PERMISSION = "needs_permission"
WAITING_SIGNOUT = "waiting_signout"
UNAVAILABLE = "unavailable"
ACCESS_STATES = (READY, NEEDS_PERMISSION, WAITING_SIGNOUT, UNAVAILABLE)


class Collector(ABC):
    id: str
    name: str
    description: str
    platform: str  # "windows" or "linux"

    @abstractmethod
    def access(self) -> str:
        """One of ACCESS_STATES. Must be cheap and must never raise."""

    @abstractmethod
    def poll(self, session: Session, setting: CollectorSettingRow) -> int:
        """Read new events and import them. Returns how many were imported.

        The collector reads and updates its bookmark through `setting` (last_record_id, backfill_hours)
        and must advance it only after a successful import. The manager commits the session afterwards.
        """
