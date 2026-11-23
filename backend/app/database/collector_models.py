"""Persistent state for the system log collectors and a tiny key-value table for app settings."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.database.models import Base


class CollectorSettingRow(Base):
    __tablename__ = "collector_settings"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    backfill_hours: Mapped[int | None] = mapped_column(Integer, nullable=True)  # one-shot: cleared once used
    last_record_id: Mapped[int] = mapped_column(Integer, default=0)  # bookmark: highest record already imported
    events_read: Mapped[int] = mapped_column(Integer, default=0)
    last_activity: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class AppSettingRow(Base):
    __tablename__ = "app_settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")


def get_setting(session: Session, key: str, default: str = "") -> str:
    row = session.get(AppSettingRow, key)
    return row.value if row else default


def set_setting(session: Session, key: str, value: str) -> None:
    row = session.get(AppSettingRow, key)
    if row is None:
        session.add(AppSettingRow(key=key, value=value))
    else:
        row.value = value
    session.flush()
