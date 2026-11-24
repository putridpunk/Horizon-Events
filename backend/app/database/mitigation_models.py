"""Every mitigation the app proposed or carried out, so the user can see and undo what happened."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.models import Base

BLOCK_IP, QUARANTINE = "block_ip", "quarantine_file"
SUGGESTED, RUNNING, DONE, FAILED, DISMISSED, UNDONE = "suggested", "running", "done", "failed", "dismissed", "undone"


class MitigationRow(Base):
    __tablename__ = "mitigations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), index=True)
    kind: Mapped[str] = mapped_column(String(24))  # block_ip | quarantine_file
    target: Mapped[str] = mapped_column(String(1024))  # the IP address or the file path
    status: Mapped[str] = mapped_column(String(16), default=SUGGESTED)
    automatic: Mapped[bool] = mapped_column(default=False)  # carried out without asking (Automatic mode)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)  # blocks only
    detail: Mapped[dict] = mapped_column(JSON, default=dict)  # message, quarantine_path, sha256, ...

    def as_dict(self, now: datetime) -> dict:
        detail = self.detail or {}
        return {
            "id": self.id, "alert_id": self.alert_id, "kind": self.kind, "target": self.target, "status": self.status,
            "automatic": self.automatic, "created_at": self.created_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "expired": bool(self.status == DONE and self.kind == BLOCK_IP and self.expires_at and self.expires_at < now),
            "message": detail.get("message", ""), "sha256": detail.get("sha256"),
        }
