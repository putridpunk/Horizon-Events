from datetime import datetime, timedelta

import pytest

from app.alerts.manager import AlertManager, InvalidTransition
from app.database.repositories import AlertRepository, EventRepository
from app.domain import AlertStatus, Detection, Severity
from tests.conftest import make_event


def det(session, ts="2026-11-23T10:00:00", sev=Severity.high, key="HZ-001|1.1.1.1|", n=1):
    t0 = datetime.fromisoformat(ts)
    evs = EventRepository(session).add_many([make_event(ts=(t0 + timedelta(seconds=i)).isoformat(),
                                                        raw=f"{ts}-{i}-{key}") for i in range(n)])
    return Detection("HZ-001", "Repeated login failures", sev, "desc", evs, "1.1.1.1", "admin", n, 5, key)


def test_creates_alert_with_formatted_id(session):
    mgr = AlertManager(AlertRepository(session))
    [a] = mgr.process([det(session, n=3)])
    assert a.alert_code == f"ALT-{a.id:06d}" and a.status == "OPEN" and a.occurrences == 3
    assert [h.to_status for h in mgr.alerts.history(a.id)] == ["OPEN"]
    assert len(mgr.alerts.linked_events(a.id)) == 3


def test_dedupes_same_key_within_window(session):
    mgr = AlertManager(AlertRepository(session))
    mgr.process([det(session, n=2)])
    [a] = mgr.process([det(session, ts="2026-11-23T10:10:00", n=4)])
    assert mgr.alerts.list()[1] == 1 and a.occurrences == 4 and len(mgr.alerts.linked_events(a.id)) == 6


def test_new_alert_after_resolved(session):
    mgr = AlertManager(AlertRepository(session))
    [a] = mgr.process([det(session)])
    mgr.change_status(a.id, AlertStatus.RESOLVED)
    mgr.process([det(session, ts="2026-11-23T10:05:00")])
    assert mgr.alerts.list()[1] == 2


def test_new_alert_outside_dedupe_window(session):
    mgr = AlertManager(AlertRepository(session), dedupe_window_minutes=30)
    mgr.process([det(session)])
    mgr.process([det(session, ts="2026-11-23T12:00:00")])
    assert mgr.alerts.list()[1] == 2


def test_severity_escalates_on_merge(session):
    mgr = AlertManager(AlertRepository(session))
    mgr.process([det(session, sev=Severity.high)])
    [a] = mgr.process([det(session, ts="2026-11-23T10:01:00", sev=Severity.critical)])
    assert a.severity == "critical"


def test_status_change_writes_history(session):
    mgr = AlertManager(AlertRepository(session))
    [a] = mgr.process([det(session)])
    mgr.change_status(a.id, AlertStatus.INVESTIGATING, "looking")
    h = mgr.alerts.history(a.id)
    assert [(x.from_status, x.to_status, x.note) for x in h][-1] == ("OPEN", "INVESTIGATING", "looking")


def test_invalid_transition_raises_and_history_unchanged(session):
    mgr = AlertManager(AlertRepository(session))
    [a] = mgr.process([det(session)])
    with pytest.raises(InvalidTransition):
        mgr.change_status(a.id, AlertStatus.OPEN)
    assert len(mgr.alerts.history(a.id)) == 1 and a.status == "OPEN"


def test_priority_orders_critical_first(session):
    mgr = AlertManager(AlertRepository(session))
    mgr.process([det(session, sev=Severity.low, key="a"), det(session, sev=Severity.critical, key="b")])
    assert [r.severity for r in mgr.alerts.list()[0]] == ["critical", "low"]
