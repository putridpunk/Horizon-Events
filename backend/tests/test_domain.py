from datetime import datetime

from app.config import get_settings
from app.domain import Event, EventType, Severity


def _ev(raw="x"):
    return Event(datetime(2026, 11, 23, 14, 20, 31), "linux_auth", EventType.generic, Severity.low, "m", raw)


def test_fingerprint_stable_for_equal_events():
    assert _ev().fingerprint() == _ev().fingerprint()


def test_fingerprint_differs_when_raw_differs():
    assert _ev("a").fingerprint() != _ev("b").fingerprint()


def test_settings_default_database_url(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert get_settings().database_url == "sqlite:///./horizon.db"
