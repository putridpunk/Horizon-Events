"""Engine and session management."""
from __future__ import annotations

from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import get_settings
from app.database import (collector_models, incident_models, ioc_models, mitigation_models,  # noqa: F401  (register their tables)
                          notification_models,
                          scan_models, search_models, suppression_models)
from app.database.models import Base


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite"):
        kwargs: dict = {"connect_args": {"check_same_thread": False}}
        if ":memory:" in url or url == "sqlite://":
            kwargs["poolclass"] = StaticPool
        return create_engine(url, **kwargs)
    return create_engine(url, pool_pre_ping=True)


@lru_cache
def get_engine() -> Engine:
    return make_engine(get_settings().database_url)


def init_db(engine: Engine | None = None) -> None:
    Base.metadata.create_all(engine or get_engine())


def get_session():
    """FastAPI dependency: one session per request."""
    session = Session(get_engine(), expire_on_commit=False)
    try:
        yield session
    finally:
        session.close()


def session_factory(engine: Engine) -> sessionmaker:
    return sessionmaker(engine, expire_on_commit=False)
