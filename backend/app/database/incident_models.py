"""Incident tables. Imported by `app.database.models` so they register on the shared metadata."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.models import Base
from app.domain import utcnow


class IncidentRow(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str | None] = mapped_column(String(16), unique=True, nullable=True)
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="OPEN")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_activity: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (Index("ix_incidents_status_severity", "status", "severity"),)


class IncidentAlertLink(Base):
    """An alert belongs to at most one incident (alert_id is the primary key)."""
    __tablename__ = "incident_alerts"
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    added_by: Mapped[str] = mapped_column(String(16), default="auto")
    added_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class IncidentExclusionRow(Base):
    """Alerts an analyst removed from an incident; automatic correlation must not re-add them."""
    __tablename__ = "incident_exclusions"
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class IncidentHistoryRow(Base):
    __tablename__ = "incident_history"
    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    action: Mapped[str] = mapped_column(String(32))
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    from_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    to_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
