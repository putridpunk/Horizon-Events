"""Users, their sign-in sessions and an audit trail. Only used when sign-in is switched on (HORIZON_AUTH=1)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.models import Base


class UserRow(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)  # stored in lower case
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))  # viewer | analyst | admin
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    last_login: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def as_dict(self) -> dict:
        return {"id": self.id, "username": self.username, "role": self.role, "disabled": self.disabled,
                "created_at": self.created_at.isoformat(),
                "last_login": self.last_login.isoformat() if self.last_login else None,
                "locked": bool(self.locked_until)}


class AuthSessionRow(Base):
    __tablename__ = "auth_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)  # SHA-256 of the cookie value
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    last_seen: Mapped[datetime] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class AuditRow(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime, index=True)
    actor: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(48))
    detail: Mapped[str] = mapped_column(String(300), default="")
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    def as_dict(self) -> dict:
        return {"id": self.id, "at": self.at.isoformat(), "actor": self.actor, "action": self.action,
                "detail": self.detail, "ip": self.ip}
