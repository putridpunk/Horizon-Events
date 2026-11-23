from datetime import datetime
from pathlib import Path

import pytest

from app.database.repositories import AlertRepository, RuleRepository
from app.detection.anomaly import AnomalousIpActivity
from app.detection.registry import DEFAULT_RULES
from app.domain import EventType
from app.ml import model as ml
from app.ml.baseline import synthetic_baseline
from app.services.ingestion import import_logs
from tests.conftest import make_event
from tests.test_rules import FakeHistory

SAMPLES = Path(__file__).resolve().parents[2] / "sample_logs"
NOW = datetime(2026, 11, 23, 23, 59)
SPRAY_IP = "198.51.100.77"


@pytest.fixture(scope="module")
def _bundle():
    return ml.train(synthetic_baseline(), "synthetic")


@pytest.fixture
def trained(_bundle, tmp_path, monkeypatch):
    path = tmp_path / "model.joblib"
    monkeypatch.setenv("HORIZON_MODEL_PATH", str(path))
    ml.save(_bundle, path)
    return path


def spray_events(n=3, ip=SPRAY_IP):
    return [make_event(ts=f"2026-11-23T10:{i * 10:02d}:00", ip=ip, user=f"user{i}") for i in range(n)]


def run(events):
    return AnomalousIpActivity().evaluate(events, FakeHistory(events))


def test_returns_empty_without_model(tmp_path, monkeypatch):
    monkeypatch.setenv("HORIZON_MODEL_PATH", str(tmp_path / "none.joblib"))
    assert run(spray_events()) == []


def test_returns_empty_with_corrupt_model(tmp_path, monkeypatch):
    bad = tmp_path / "bad.joblib"
    bad.write_bytes(b"garbage")
    monkeypatch.setenv("HORIZON_MODEL_PATH", str(bad))
    assert run(spray_events()) == []


def test_min_events_guard(trained):
    assert run(spray_events(n=2)) == []


def test_spray_ip_flagged_with_explanation(trained):
    [d] = run(spray_events())
    assert d.rule_id == "HZ-007" and d.key == f"HZ-007|{SPRAY_IP}|" and d.window_minutes == 60
    assert "failures" in d.description and d.occurrences == 3


def test_typical_activity_not_flagged(trained):
    evs = [make_event(EventType.authentication_success, ts=f"2026-11-23T10:0{i}:00", ip="10.0.0.5", user="u",
                      raw=f"ok{i}") for i in range(2)] + [
        make_event(EventType.authentication_success, ts="2026-11-23T10:09:00", ip="10.0.0.5", user="u", raw="ok9")]
    assert run(evs) == []


def test_seed_defaults_adds_missing_rule_and_keeps_edits(session):
    repo = RuleRepository(session)
    repo.seed_defaults(DEFAULT_RULES[:6])
    repo.update("HZ-001", params={"threshold": 9})
    repo.seed_defaults(DEFAULT_RULES)
    rules = {r.id: r for r in repo.list()}
    assert len(rules) == 7 and "HZ-007" in rules and rules["HZ-001"].params["threshold"] == 9


def test_import_creates_hz007_and_no_hz001_for_spray(session, trained):
    import_logs(session, "linux_auth", "slow_spray.log", (SAMPLES / "slow_spray.log").read_bytes(), NOW)
    alerts = AlertRepository(session)
    rows, _ = alerts.list(rule_id="HZ-007")
    assert [a.source_ip for a in rows] == [SPRAY_IP]
    assert alerts.list(rule_id="HZ-001")[1] == 0


def test_reimport_creates_no_duplicate_alert(session, trained):
    data = (SAMPLES / "slow_spray.log").read_bytes()
    import_logs(session, "linux_auth", "slow_spray.log", data, NOW)
    second = import_logs(session, "linux_auth", "slow_spray.log", data, NOW)
    assert second["alerts_created"] == 0 and AlertRepository(session).list(rule_id="HZ-007")[1] == 1
