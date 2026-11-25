"""Patterns the user marked as known false positives: matching detections no longer raise alerts."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.models import Base


class SuppressionRow(Base):
    __tablename__ = "suppressions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # every field that is set must match; at least one must be set (see alerts/suppression.py)
    rule_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    note: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime)
    hits: Mapped[int] = mapped_column(Integer, default=0)  # detections it has silenced
    last_hit: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def as_dict(self) -> dict:
        return {
            "id": self.id, "rule_id": self.rule_id, "source_ip": self.source_ip, "username": self.username,
            "note": self.note, "created_at": self.created_at.isoformat(), "hits": self.hits,
            "last_hit": self.last_hit.isoformat() if self.last_hit else None,
        }
