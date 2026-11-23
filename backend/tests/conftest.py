from datetime import datetime

import pytest
from sqlalchemy.orm import Session

from app.database.connection import init_db, make_engine
from app.domain import Event, EventType, Severity


@pytest.fixture
def engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


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
