"""Tables for notification channels, alert triage (owner, tags) and scheduled reports. New tables only, so an
existing database gains them automatically on start."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.models import Base


class NotificationChannelRow(Base):
    __tablename__ = "notification_channels"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    kind: Mapped[str] = mapped_column(String(16))  # webhook | slack | discord | email
    config: Mapped[dict] = mapped_column(JSON, default=dict)  # holds secrets; never returned by the API as is
    min_severity: Mapped[str] = mapped_column(String(16), default="high")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    last_sent: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    sent_count: Mapped[int] = mapped_column(Integer, default=0)


class AlertMetaRow(Base):
    __tablename__ = "alert_meta"
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), primary_key=True)
    assignee: Mapped[str | None] = mapped_column(String(100), nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)


class ReportScheduleRow(Base):
    __tablename__ = "report_schedules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    frequency: Mapped[str] = mapped_column(String(8))  # daily | weekly
    format: Mapped[str] = mapped_column(String(8), default="html")
    email_channel_id: Mapped[int | None] = mapped_column(ForeignKey("notification_channels.id"), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    next_run: Mapped[datetime] = mapped_column(DateTime)
    last_run: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_file: Mapped[str | None] = mapped_column(String(500), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
