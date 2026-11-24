"""A record of each file scan the user started (what was scanned and what came of it)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.models import Base


class ScanRow(Base):
    __tablename__ = "file_scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="running")  # running | completed | failed
    targets: Mapped[list] = mapped_column(JSON, default=list)  # the paths the user chose
    # one entry per target, filled in as the scan advances:
    # {path, status: clean|threat|error, message, threats: [{threat, path, sha256, alert_id}]}
    results: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    def as_dict(self) -> dict:
        return {
            "id": self.id, "created_at": self.created_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "status": self.status, "targets": self.targets, "results": self.results, "error": self.error,
            "done": len(self.results), "total": len(self.targets),
            "threats": sum(len(r.get("threats", [])) for r in self.results),
        }
