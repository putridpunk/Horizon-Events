"""Searches the user saved to run again. A new table, so existing databases gain it on start."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.models import Base


class SavedSearchRow(Base):
    __tablename__ = "saved_searches"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    query: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime)

    def as_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "query": self.query, "created_at": self.created_at.isoformat()}
