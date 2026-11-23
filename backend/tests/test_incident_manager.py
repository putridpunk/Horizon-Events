from datetime import datetime

import pytest

from app.alerts.manager import InvalidTransition
from app.database.incident_repository import IncidentRepository
from app.database.repositories import AlertRepository
from app.domain import AlertStatus
from app.incidents.manager import IncidentManager


@pytest.fixture
def mgr(session):
    return IncidentManager(IncidentRepository(session))


def mk(session, rule="HZ-001", name="Repeated login failures", sev="high", ip="1.1.1.1", user=None,
       seen="2026-11-23T10:00:00"):
    return AlertRepository(session).create(
        rule_id=rule, rule_name=name, severity=sev, status="OPEN", key=f"{rule}|{ip}|{user}|{seen}",
        source_ip=ip, username=user, last_seen=datetime.fromisoformat(seen))


def incidents(mgr):
    return mgr.repo.list(limit=100)[0]


def test_new_alert_creates_incident_with_code_and_title(session, mgr):
    mgr.correlate([mk(session)])
    [inc] = incidents(mgr)
    assert inc.code == f"INC-{inc.id:06d}" and inc.title == "Repeated login failures from 1.1.1.1"
    assert inc.status == "OPEN" and mgr.repo.history(inc.id)[0].action == "created"
    assert mk(session, ip=None, user="bob").username == "bob"


def test_username_only_alert_title(session, mgr):
    mgr.correlate([mk(session, ip=None, user="bob", name="Account lockouts")])
    assert incidents(mgr)[0].title == "Account lockouts on account bob"


def test_same_ip_joins_existing_incident(session, mgr):
    mgr.correlate([mk(session), mk(session, rule="HZ-006", name="Account lockouts", seen="2026-11-23T11:00:00")])
    [inc] = incidents(mgr)
    assert mgr.repo.alert_count(inc.id) == 2


def test_same_username_joins(session, mgr):
    mgr.correlate([mk(session, ip="1.1.1.1", user="admin"),
                   mk(session, rule="HZ-006", ip="2.2.2.2", user="admin", seen="2026-11-23T10:30:00")])
    assert len(incidents(mgr)) == 1


def test_different_keys_do_not_join(session, mgr):
    mgr.correlate([mk(session, ip="1.1.1.1", user="a"), mk(session, ip="2.2.2.2", user="b")])
    assert len(incidents(mgr)) == 2


def test_more_than_24h_apart_does_not_join(session, mgr):
    mgr.correlate([mk(session), mk(session, rule="HZ-006", seen="2026-11-24T11:00:00")])
    assert len(incidents(mgr)) == 2


def test_resolved_incident_not_joined(session, mgr):
    mgr.correlate([mk(session)])
    mgr.change_status(incidents(mgr)[0].id, AlertStatus.RESOLVED)
    mgr.correlate([mk(session, rule="HZ-006", seen="2026-11-23T10:30:00")])
    assert len(incidents(mgr)) == 2


def test_alert_without_ip_or_username_not_grouped(session, mgr):
    mgr.correlate([mk(session, ip=None, user=None, rule="HZ-005", name="Service failures")])
    assert incidents(mgr) == []


def test_severity_is_maximum_and_refreshes(session, mgr):
    a1 = mk(session, sev="high")
    mgr.correlate([a1])
    assert incidents(mgr)[0].severity == "high"
    a2 = mk(session, rule="HZ-007", sev="critical", seen="2026-11-23T12:00:00")
    mgr.correlate([a2])
    inc = incidents(mgr)[0]
    assert inc.severity == "critical" and inc.last_activity == datetime(2026, 11, 23, 12)
    a1.severity = "low"
    a2.severity = "low"
    mgr.correlate([a1])  # an alert already in an incident refreshes it
    assert incidents(mgr)[0].severity == "low"


def test_correlate_is_idempotent(session, mgr):
    alerts = [mk(session), mk(session, rule="HZ-006", seen="2026-11-23T11:00:00")]
    mgr.correlate(alerts)
    inc = incidents(mgr)[0]
    before = len(mgr.repo.history(inc.id))
    mgr.correlate(alerts)
    assert len(incidents(mgr)) == 1 and len(mgr.repo.history(inc.id)) == before


def test_backfill_is_idempotent(session, mgr):
    for i in range(3):
        mk(session, ip=f"9.9.9.{i}")
    mk(session, ip=None, user=None, rule="HZ-005")
    assert mgr.backfill() == 3 and len(incidents(mgr)) == 3
    assert mgr.backfill() == 0 and len(incidents(mgr)) == 3


def test_add_alert_moves_between_incidents_and_audits_both(session, mgr):
    a1, a2 = mk(session, ip="1.1.1.1"), mk(session, ip="2.2.2.2")
    mgr.correlate([a1, a2])
    inc1, inc2 = sorted(incidents(mgr), key=lambda i: i.id)
    mgr.add_alert(inc2.id, a1.id)
    assert mgr.repo.alert_count(inc2.id) == 2 and mgr.repo.alert_count(inc1.id) == 0
    assert "alert_removed" in [h.action for h in mgr.repo.history(inc1.id)]
    assert mgr.repo.history(inc2.id)[-1].action == "alert_added"
    assert mgr.add_alert(inc2.id, a1.id).id == inc2.id  # adding again is a no-op
    with pytest.raises(LookupError):
        mgr.add_alert(inc2.id, 9999)


def test_removed_alert_not_recorrelated(session, mgr):
    a = mk(session)
    mgr.correlate([a])
    inc = incidents(mgr)[0]
    mgr.remove_alert(inc.id, a.id)
    assert mgr.repo.incident_for_alert(a.id) is None
    mgr.correlate([a])
    assert mgr.repo.incident_for_alert(a.id) is None and mgr.backfill() == 0
    with pytest.raises(LookupError):
        mgr.remove_alert(inc.id, a.id)


def test_merge_moves_alerts_and_marks_source(session, mgr):
    mgr.correlate([mk(session, ip="1.1.1.1"), mk(session, ip="2.2.2.2"), mk(session, ip="3.3.3.3")])
    a, b, _ = sorted(incidents(mgr), key=lambda i: i.id)
    mgr.merge(a.id, b.id)
    assert mgr.repo.alert_count(b.id) == 2 and mgr.repo.alert_count(a.id) == 0
    assert a.status == "RESOLVED" and "merged" in [h.action for h in mgr.repo.history(a.id)]
    assert "merged" in [h.action for h in mgr.repo.history(b.id)]


def test_merge_into_self_missing_or_resolved_rejected(session, mgr):
    mgr.correlate([mk(session, ip="1.1.1.1"), mk(session, ip="2.2.2.2")])
    a, b = sorted(incidents(mgr), key=lambda i: i.id)
    with pytest.raises(ValueError):
        mgr.merge(a.id, a.id)
    with pytest.raises(LookupError):
        mgr.merge(a.id, 9999)
    mgr.change_status(b.id, AlertStatus.RESOLVED)
    with pytest.raises(ValueError):
        mgr.merge(a.id, b.id)


def test_status_transitions_audited_and_invalid_rejected(session, mgr):
    mgr.correlate([mk(session)])
    inc = incidents(mgr)[0]
    mgr.change_status(inc.id, AlertStatus.INVESTIGATING, "looking")
    last = mgr.repo.history(inc.id)[-1]
    assert (last.action, last.from_status, last.to_status, last.detail) == (
        "status_changed", "OPEN", "INVESTIGATING", "looking")
    count = len(mgr.repo.history(inc.id))
    with pytest.raises(InvalidTransition):
        mgr.change_status(inc.id, AlertStatus.INVESTIGATING)
    assert len(mgr.repo.history(inc.id)) == count and inc.status == "INVESTIGATING"
    with pytest.raises(LookupError):
        mgr.change_status(9999, AlertStatus.RESOLVED)


def test_note_and_title_audited(session, mgr):
    mgr.correlate([mk(session)])
    inc = incidents(mgr)[0]
    mgr.add_note(inc.id, "  called the owner  ")
    mgr.set_title(inc.id, "SSH brute force")
    actions = [(h.action, h.detail) for h in mgr.repo.history(inc.id)]
    assert ("note", "called the owner") in actions and inc.title == "SSH brute force"
    assert any(a == "title_changed" for a, _ in actions)
    with pytest.raises(ValueError):
        mgr.add_note(inc.id, "   ")
    with pytest.raises(ValueError):
        mgr.set_title(inc.id, "")
