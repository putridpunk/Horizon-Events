from datetime import datetime

from sqlalchemy import inspect

from app.database.repositories import AlertRepository, EventRepository
from app.domain import EventType
from tests.conftest import make_event


def test_add_many_dedupes_by_fingerprint(session):
    repo = EventRepository(session)
    e = make_event()
    assert len(repo.add_many([e, make_event()])) == 1  # duplicate inside the batch
    assert len(repo.add_many([make_event()])) == 0  # duplicate against the DB
    assert repo.add_many([make_event(ts="2026-11-23T10:00:01")])[0].id is not None


def test_search_filters_and_pagination(session):
    repo = EventRepository(session)
    repo.add_many([make_event(ts=f"2026-11-23T10:00:{i:02d}", ip="9.9.9.9" if i % 2 else "1.1.1.1")
                   for i in range(10)] + [make_event(EventType.account_lockout, ts="2026-11-23T11:00:00")])
    rows, total = repo.search(event_type="authentication_failure", limit=3, offset=0)
    assert (len(rows), total) == (3, 10)
    assert repo.search(q="9.9.9.9")[1] == 5
    assert repo.search(start=datetime(2026, 11, 23, 10, 30))[1] == 1


def test_count_in_window_by_ip(session):
    repo = EventRepository(session)
    repo.add_many([make_event(ts=f"2026-11-23T10:0{i}:00") for i in range(5)] +
                  [make_event(ts="2026-11-23T10:00:00", ip="2.2.2.2", raw="other")])
    n = repo.count_in_window([EventType.authentication_failure], datetime(2026, 11, 23, 10, 0),
                             datetime(2026, 11, 23, 10, 3), source_ip="1.1.1.1")
    assert n == 4


def test_alert_filters_and_priority(session):
    a = AlertRepository(session)
    for sev in ("low", "critical", "high"):
        a.create(rule_id="HZ-001", rule_name="r", severity=sev, status="OPEN", key=sev)
    a.create(rule_id="HZ-002", rule_name="r", severity="high", status="RESOLVED", key="x")
    rows, total = a.list()
    assert [r.severity for r in rows][:2] == ["critical", "high"] and total == 4
    assert a.list(status="RESOLVED")[1] == 1 and a.list(severity="low")[1] == 1
    assert rows[0].alert_code == f"ALT-{rows[0].id:06d}"


def test_indexes_exist(engine):
    insp = inspect(engine)
    cols = {tuple(i["column_names"]) for i in insp.get_indexes("events")}
    assert {("timestamp",), ("event_type",), ("source_ip",)} <= cols
    assert ("status", "severity") in {tuple(i["column_names"]) for i in insp.get_indexes("alerts")}


def test_alert_event_link_roundtrip(session):
    ev = EventRepository(session).add_many([make_event()])[0]
    a = AlertRepository(session)
    alert = a.create(rule_id="HZ-001", rule_name="r", severity="high", status="OPEN", key="k")
    a.link_events(alert.id, [ev.id])
    a.link_events(alert.id, [ev.id])  # idempotent
    assert [r.id for r in a.linked_events(alert.id)] == [ev.id]
