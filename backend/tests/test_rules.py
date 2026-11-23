from datetime import datetime, timedelta

from app.detection.engine import DetectionEngine
from app.detection.registry import DEFAULT_RULES
from app.detection.rules import (AccountLockouts, PrivilegeEscalation, RepeatedLoginFailures, ServiceFailures,
                                 UnknownUsers, UnusualLoginHours)
from app.domain import EventType, Severity
from tests.conftest import make_event


class FakeHistory:
    """In-memory EventHistory; assigns ids like the repository does."""

    def __init__(self, events):
        self.events = events
        for i, e in enumerate(events, 1):
            e.id = i

    def events_in_window(self, event_types, since, until, source_ip=None, username=None, service=None):
        return [e for e in self.events if e.event_type in event_types and since <= e.timestamp <= until
                and (source_ip is None or e.source_ip == source_ip)
                and (username is None or e.username == username)
                and (service is None or e.service == service)]


def fails(n, start="2026-11-23T10:00:00", step=10, ip="1.1.1.1"):
    t0 = datetime.fromisoformat(start)
    return [make_event(ts=(t0 + timedelta(seconds=i * step)).isoformat(), ip=ip) for i in range(n)]


def run(rule, events):
    h = FakeHistory(events)
    return rule.evaluate(events, h)


def test_hz001_fires_at_5_not_at_4():
    assert run(RepeatedLoginFailures(), fails(4)) == []
    d = run(RepeatedLoginFailures(), fails(5))
    assert len(d) == 1 and d[0].severity == Severity.high and d[0].occurrences == 5 and d[0].source_ip == "1.1.1.1"


def test_hz001_critical_at_10():
    assert run(RepeatedLoginFailures(), fails(10))[0].severity == Severity.critical


def test_hz001_window_excludes_old_events():
    assert run(RepeatedLoginFailures(), fails(5, step=120)) == []  # 8 minutes apart in total
    assert len(run(RepeatedLoginFailures(), fails(5, step=60))) == 1  # exactly within 5 minutes


def test_hz001_groups_by_ip():
    evs = fails(3, ip="1.1.1.1") + fails(3, ip="2.2.2.2")
    assert run(RepeatedLoginFailures(), evs) == []


def test_hz001_params_override_defaults():
    assert len(run(RepeatedLoginFailures(params={"threshold": 3}), fails(3))) == 1


def test_hz001_old_burst_in_history_does_not_refire():
    old = fails(6, start="2026-11-23T08:00:00")
    new = fails(1, start="2026-11-23T12:00:00")
    h = FakeHistory(old + new)
    assert RepeatedLoginFailures().evaluate(new, h) == []


def test_hz002_hours_and_weekend():
    ok = make_event(EventType.authentication_success, ts="2026-11-23T10:00:00")  # Monday 10:00
    late = make_event(EventType.authentication_success, ts="2026-11-23T23:40:00", user="alice")
    assert [d.username for d in run(UnusualLoginHours(), [ok, late])] == ["alice"]
    sat = make_event(EventType.authentication_success, ts="2026-11-28T10:00:00")
    assert len(run(UnusualLoginHours(), [sat])) == 1
    assert run(UnusualLoginHours(params={"weekends": False}), [sat]) == []


def test_hz003_single_medium_three_high():
    one = [make_event(EventType.unknown_user, user="ghost")]
    assert run(UnknownUsers(), one)[0].severity == Severity.medium
    three = [make_event(EventType.unknown_user, ts=f"2026-11-23T10:00:0{i}", user=f"u{i}", ip="9.9.9.9")
             for i in range(3)]
    d = run(UnknownUsers(), three)
    assert len(d) == 1 and d[0].severity == Severity.high and d[0].occurrences == 3


def test_hz004_allowlist():
    root = make_event(EventType.privilege_escalation, user="root")
    bob = make_event(EventType.privilege_escalation, user="bob", ip=None)
    assert [d.username for d in run(PrivilegeEscalation(), [root, bob])] == ["bob"]


def test_hz005_three_failures_same_service():
    mk = lambda i, s: make_event(EventType.service_failure, ts=f"2026-11-23T10:0{i}:00", service=s, ip=None)
    assert len(run(ServiceFailures(), [mk(0, "nginx"), mk(1, "nginx"), mk(2, "nginx")])) == 1
    assert run(ServiceFailures(), [mk(0, "nginx"), mk(1, "nginx"), mk(2, "cron")]) == []


def test_hz006_lockout():
    d = run(AccountLockouts(), [make_event(EventType.account_lockout, user="admin")])
    assert len(d) == 1 and d[0].severity == Severity.high


def test_engine_runs_only_enabled_rules():
    defs = [dict(r) for r in DEFAULT_RULES]
    for r in defs:
        r["enabled"] = r["id"] == "HZ-006"
    engine = DetectionEngine.from_definitions(defs)
    evs = fails(10) + [make_event(EventType.account_lockout, user="x", ip=None)]
    d = engine.run(evs, FakeHistory(evs))
    assert [x.rule_id for x in d] == ["HZ-006"]
