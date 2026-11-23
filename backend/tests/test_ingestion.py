from datetime import datetime
from pathlib import Path

from app.database.repositories import AlertRepository, EventRepository
from app.seed import seed
from app.services.ingestion import import_logs

SAMPLES = Path(__file__).resolve().parents[2] / "sample_logs"
NOW = datetime(2026, 11, 23, 23, 59, 0)


def test_full_import_generates_expected_alerts(session):
    seed(session, SAMPLES, NOW)
    alerts, _ = AlertRepository(session).list(limit=100)
    by_rule = {}
    for a in alerts:
        by_rule.setdefault(a.rule_id, []).append(a)
    assert set(by_rule) == {"HZ-001", "HZ-002", "HZ-003", "HZ-004", "HZ-005", "HZ-006"}
    brute = by_rule["HZ-001"][0]
    assert (brute.severity, brute.source_ip, brute.username, brute.occurrences) == ("critical", "192.168.1.15", "admin", 12)
    assert alerts[0].severity == "critical"
    assert EventRepository(session).search()[1] > 40


def test_importing_same_file_twice_adds_nothing(session):
    data = (SAMPLES / "linux_auth.log").read_bytes()
    first = import_logs(session, "linux_auth", "a.log", data, NOW)
    total_alerts = AlertRepository(session).list()[1]
    second = import_logs(session, "linux_auth", "a.log", data, NOW)
    assert second["imported"] == 0 and second["duplicates"] == first["imported"] and second["alerts_created"] == 0
    assert AlertRepository(session).list()[1] == total_alerts


def test_empty_file_import(session):
    res = import_logs(session, "linux_auth", "empty.log", b"", NOW)
    assert (res["total"], res["imported"], res["skipped"], res["alerts_created"]) == (0, 0, 0, 0)


def test_mixed_garbage_counts_skipped(session):
    res = import_logs(session, "linux_auth", "m.log", b"junk\nNov 23 10:00:00 s sshd[1]: Accepted password for a from 1.1.1.1 p\n\x00\xff\n", NOW)
    assert res["imported"] == 1 and res["skipped"] == 2
