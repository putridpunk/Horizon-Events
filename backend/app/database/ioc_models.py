"""File hashes and domain names from imported threat lists. (Imported IP addresses go in the existing IntelEntryRow.)"""
from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.models import Base


class IocRow(Base):
    __tablename__ = "intel_iocs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    feed_id: Mapped[str] = mapped_column(ForeignKey("intel_feeds.id"), index=True)
    kind: Mapped[str] = mapped_column(String(8))  # sha256 | sha1 | md5 | domain
    value: Mapped[str] = mapped_column(String(255), index=True)  # lower case
