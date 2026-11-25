import pytest

from app.collectors.base import collect
from app.database.repositories import EventRepository
from app.detection.registry import DEFAULT_RULES, RULE_CLASSES
from app.detection.windows_rules import AuditLogCleared, RemoteDesktopLogin, ScheduledTaskCreated, ServiceInstalled
from app.domain import Severity
from app.mitigation.advice import ADVICE
from app.mitre import RULE_TECHNIQUES, TECHNIQUES, techniques_for_rule
from tests import eventlog_samples as s


def events(session, *xml):
    found, result = collect("windows", s.wrap(*xml).encode("utf-8"))
    assert result.skipped == 0
    return EventRepository(session).add_many(found)


# ---- parsing the new events ------------------------------------------------------------------------------------
@pytest.mark.parametrize("xml,etype,user", [
    (s.log_cleared(1), "log_cleared", "mallory"), (s.log_cleared(2, event_id=104), "log_cleared", "mallory"),
    (s.service_installed(3), "service_installed", "mallory"), (s.service_installed(4, event_id=4697), "service_installed", "mallory"),
    (s.task_created(5), "scheduled_task_created", "mallory"),
])
def test_new_windows_events_are_recognised(xml, etype, user):
    [e] = collect("windows", s.wrap(xml).encode("utf-8"))[0]
    assert e.event_type.value == etype and e.username == user


def test_service_and_task_names_are_kept():
    found = collect("windows", s.wrap(s.service_installed(1, name="EvilSvc"), s.task_created(2, name=r"\Updater")).encode())[0]
    assert [e.service for e in found] == ["EvilSvc", r"\Updater"]
    assert "EvilSvc" in found[0].message and r"\Updater" in found[1].message


def test_a_logon_type_10_success_is_a_remote_desktop_logon():
    [e] = collect("windows", s.wrap(s.logon_success(1, user="alice", logon_type=10, ip="203.0.113.9")).encode())[0]
    assert e.event_type.value == "remote_login" and e.source_ip == "203.0.113.9"
    [local] = collect("windows", s.wrap(s.logon_success(2, logon_type=2)).encode())[0]
    assert local.event_type.value == "authentication_success"


# ---- rules -----------------------------------------------------------------------------------------------------
def test_clearing_the_log_is_critical(session):
    [d] = AuditLogCleared().evaluate(events(session, s.log_cleared(1)), None)
    assert d.rule_id == "HZ-009" and d.severity is Severity.critical and d.username == "mallory"


def test_a_new_service_raises_one_alert_per_service_name(session):
    ds = ServiceInstalled().evaluate(events(session, s.service_installed(1, "A"), s.service_installed(2, "B"), s.service_installed(3, "A", when="2026-11-23T03:16:00")), None)
    assert sorted(d.key for d in ds) == ["HZ-010|A|", "HZ-010|B|"]
    assert next(d for d in ds if d.key.endswith("|A|")).occurrences == 2
    assert all(d.severity is Severity.medium and "service" in d.description for d in ds)


def test_services_can_be_ignored_by_name(session):
    rule = ServiceInstalled(params={"ignore": ["Trusted"]})
    assert rule.evaluate(events(session, s.service_installed(1, "TrustedUpdater")), None) == []
    assert len(rule.evaluate(events(session, s.service_installed(2, "Other")), None)) == 1


def test_windows_own_scheduled_tasks_are_ignored_by_default(session):
    rule = ScheduledTaskCreated()
    assert rule.evaluate(events(session, s.task_created(1, r"\Microsoft\Windows\UpdateOrchestrator\Reboot")), None) == []
    [d] = rule.evaluate(events(session, s.task_created(2, r"\Updater")), None)
    assert d.rule_id == "HZ-011" and r"\Updater" in d.description


def test_remote_desktop_from_a_public_address_is_high_and_from_the_lan_is_medium(session):
    ds = RemoteDesktopLogin().evaluate(events(
        session, s.logon_success(1, "alice", 10, "8.8.4.4"), s.logon_success(2, "bob", 10, "192.168.1.20")), None)
    by_ip = {d.source_ip: d.severity for d in ds}
    assert by_ip == {"8.8.4.4": Severity.high, "192.168.1.20": Severity.medium}


def test_other_events_do_not_trigger_the_new_rules(session):
    evs = events(session, s.logon_success(1), s.lockout(2), s.logon_failure(3))
    for rule in (AuditLogCleared(), ServiceInstalled(), ScheduledTaskCreated(), RemoteDesktopLogin()):
        assert rule.evaluate(evs, None) == []


def test_remote_desktop_logins_still_count_for_unusual_hours(session):
    from app.detection.rules import UnusualLoginHours
    evs = events(session, s.logon_success(1, "alice", 10, "8.8.4.4", when="2026-11-23T03:00:00"))
    assert len(UnusualLoginHours().evaluate(evs, None)) == 1


# ---- every rule is complete ------------------------------------------------------------------------------------
def test_every_rule_has_advice_and_mitre_context():
    ids = {r["id"] for r in DEFAULT_RULES}
    assert {"HZ-009", "HZ-010", "HZ-011", "HZ-012"} <= ids <= set(ADVICE)
    for rid in ("HZ-009", "HZ-010", "HZ-011", "HZ-012"):
        assert rid in RULE_CLASSES and techniques_for_rule(rid)
    assert all(t in TECHNIQUES for maps in RULE_TECHNIQUES.values() for t, _ in maps)
