"""Application settings, read from environment variables."""
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    database_url: str = "sqlite:///./horizon.db"
    max_upload_bytes: int = 10_485_760
    work_start: int = 8
    work_end: int = 18
    cors_origins: tuple = ("http://localhost:5173",)


def get_settings() -> Settings:
    origins = os.environ.get("CORS_ORIGINS")
    return Settings(
        database_url=os.environ.get("DATABASE_URL", "sqlite:///./horizon.db"),
        cors_origins=tuple(o.strip() for o in origins.split(",")) if origins else ("http://localhost:5173",),
    )
