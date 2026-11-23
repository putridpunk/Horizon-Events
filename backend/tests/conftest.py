import os
from datetime import datetime

# The API refuses unknown Host headers; Starlette's test client uses 'testserver'. Set before the app is imported.
os.environ.setdefault("HORIZON_ALLOWED_HOSTS", "testserver")

import pytest
from sqlalchemy.orm import Session

from app.database.connection import init_db, make_engine
from app.database.models import Base
from app.domain import Event, EventType, Severity


@pytest.fixture
def engine():
    """In-memory SQLite by default. Set HORIZON_TEST_DATABASE_URL to run the suite against another
    database (e.g. PostgreSQL); the schema is recreated for every test."""
    url = os.environ.get("HORIZON_TEST_DATABASE_URL")
    if not url:
        eng = make_engine("sqlite://")
        init_db(eng)
        yield eng
        return
    eng = make_engine(url)
    Base.metadata.drop_all(eng)
    init_db(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def session(engine):
    with Session(engine, expire_on_commit=False) as s:
        yield s


def make_event(etype=EventType.authentication_failure, ts="2026-11-23T10:00:00", ip="1.1.1.1", user="admin",
               service=None, raw=None, severity=Severity.medium, source="linux_auth"):
    t = datetime.fromisoformat(ts)
    return Event(timestamp=t, source=source, event_type=etype, severity=severity, message="m",
                 raw=raw or f"{etype.value}|{ts}|{ip}|{user}|{service}", username=user, source_ip=ip,
                 service=service)
