import os
import sys

import pytest
from sqlalchemy.orm import Session

from app.database.collector_models import CollectorSettingRow
from app.database.repositories import AlertRepository, EventRepository
from app.system import windows_eventlog as wel
from app.system.base import NEEDS_PERMISSION, READY, UNAVAILABLE
from app.system.manager import CollectorManager
from app.system.windows_eventlog import CHANNELS, CollectorError, WindowsEventLogCollector, build_query
from tests import eventlog_samples as s


class FakeWevtutil:
    """Stands in for `wevtutil`: scripted batches for normal queries, a fixed answer for probes and 'newest'."""

    def __init__(self, batches=(), newest_id=None, probe_rc=0, poll_rc=0):
        self.batches, self.newest_id, self.probe_rc, self.poll_rc = list(batches), newest_id, probe_rc, poll_rc
        self.calls = []

    def __call__(self, args):
        self.calls.append(args)
        query = next((a for a in args if a.startswith("/q:")), "")
        if "EventID=0" in query:  # the access probe
            return self.probe_rc, ""
        if "/rd:true" in args:  # newest record
            return (0, s.event_xml("System", 1, self.newest_id)) if self.newest_id else (0, "")
        if self.poll_rc:
            return self.poll_rc, ""
        return 0, (self.batches.pop(0) if self.batches else "")

    @property
    def queries(self):
        return [a[len("/q:"):] for call in self.calls for a in call if a.startswith("/q:") and "EventID=0" not in a]


def make(channel="System", **fake_kw):
    fake = FakeWevtutil(**fake_kw)
    return WindowsEventLogCollector(channel, runner=fake), fake


def setting(session, collector, **kw):
    row = CollectorSettingRow(id=collector.id, enabled=True, **kw)
    session.add(row)
    session.flush()
    return row


def event_count(session):
    return EventRepository(session).search()[1]


# -- queries ---------------------------------------------------------------------------------
def test_query_for_each_channel():
    assert build_query(CHANNELS["System"], None) == "*[System[(EventID=7031 or EventID=7034 or EventID=7045 or EventID=104)]]"
    assert build_query(CHANNELS["System"], 123) == "*[System[(EventID=7031 or EventID=7034 or EventID=7045 or EventID=104) and (EventRecordID>123)]]"
    assert build_query(CHANNELS["Application"], 5) == "*[System[(EventID=1000) and (EventRecordID>5)]]"
    assert build_query(CHANNELS["Security"], 7) == (
        "*[System[(EventID=4625 or EventID=4740 or EventID=4720 or EventID=4728 or EventID=4732 or EventID=4756 or EventID=1102 or EventID=4697 or EventID=4698) "
        "and (EventRecordID>7)]] or *[System[(EventID=4624) and (EventRecordID>7)] and EventData["
        "(Data[@Name='LogonType']='2') or (Data[@Name='LogonType']='7') or (Data[@Name='LogonType']='10') or "
        "(Data[@Name='LogonType']='11')]]")


def test_backfill_query_uses_a_time_window():
    assert build_query(CHANNELS["System"], None, backfill_ms=86_400_000) == (
        "*[System[(EventID=7031 or EventID=7034 or EventID=7045 or EventID=104) and TimeCreated[timediff(@SystemTime) <= 86400000]]]")


def test_only_the_listed_events_are_ever_requested():
    for spec in CHANNELS.values():
        q = build_query(spec, 1)
        assert "4672" not in q and "4688" not in q


@pytest.mark.skipif(sys.platform != "win32", reason="needs the Windows wevtutil tool")
def test_security_shaped_query_is_accepted_by_real_wevtutil():
    # Run the Security query shape against the System channel (readable without permission): only the
    # syntax is being checked, not the content.
    rc, _ = wel.run_wevtutil(["qe", "System", f"/q:{build_query(CHANNELS['Security'], 0)}", "/c:1", "/f:xml"])
    assert rc == 0


# -- access ----------------------------------------------------------------------------------
@pytest.mark.parametrize("rc,state", [(0, READY), (5, NEEDS_PERMISSION), (15007, UNAVAILABLE),
                                      (15001, UNAVAILABLE), (1, UNAVAILABLE)])
def test_exit_codes_map_to_states(rc, state):
    collector, _ = make(probe_rc=rc)
    assert collector.access() == state


def test_timeout_while_probing_is_unavailable_not_a_crash():
    def runner(args):
        raise TimeoutError("wevtutil timed out")
    assert WindowsEventLogCollector("System", runner=runner).access() == UNAVAILABLE


def test_refine_hook_can_override_the_state():
    fake = FakeWevtutil(probe_rc=5)
    collector = WindowsEventLogCollector("Security", runner=fake, refine=lambda probe: "waiting_signout")
    assert collector.access() == "waiting_signout"


# -- polling ---------------------------------------------------------------------------------
def test_first_poll_starts_from_now_without_importing_history(session):
    collector, fake = make(newest_id=500, batches=[s.wrap(s.service_crash(7))])
    row = setting(session, collector)
    assert collector.poll(session, row) == 0
    assert row.last_record_id == 500 and event_count(session) == 0
    assert fake.queries == []  # no history query was even run


def test_backfill_imports_the_window_once_then_starts_following(session):
    batch = s.wrap(s.service_crash(11), s.service_crash(12), s.service_crash(13))
    collector, fake = make(newest_id=999, batches=[batch])
    row = setting(session, collector, backfill_hours=24)
    assert collector.poll(session, row) == 3
    assert row.last_record_id == 13 and row.backfill_hours is None and event_count(session) == 3
    assert "timediff(@SystemTime) <= 86400000" in fake.queries[0]


def test_backfill_with_no_matching_events_still_ends_at_now(session):
    collector, _ = make(newest_id=77, batches=[])
    row = setting(session, collector, backfill_hours=24)
    assert collector.poll(session, row) == 0
    assert row.last_record_id == 77 and row.backfill_hours is None


def test_poll_imports_and_advances_the_bookmark(session):
    collector, fake = make(batches=[s.wrap(s.service_crash(101), s.service_crash(102))])
    row = setting(session, collector, last_record_id=100)
    assert collector.poll(session, row) == 2
    assert row.last_record_id == 102 and event_count(session) == 2
    assert fake.queries == ["*[System[(EventID=7031 or EventID=7034 or EventID=7045 or EventID=104) and (EventRecordID>100)]]"]


def test_batches_repeat_until_a_short_batch(session, monkeypatch):
    monkeypatch.setattr(wel, "BATCH_SIZE", 2)
    collector, fake = make(batches=[s.wrap(s.service_crash(1), s.service_crash(2)),
                                    s.wrap(s.service_crash(3), s.service_crash(4)), s.wrap(s.service_crash(5))])
    row = setting(session, collector, last_record_id=1)
    assert collector.poll(session, row) == 5
    assert row.last_record_id == 5
    assert [q.split("EventRecordID>")[1].split(")")[0] for q in fake.queries] == ["1", "2", "4"]


def test_failed_import_keeps_the_bookmark(session, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("database is locked")
    monkeypatch.setattr(wel, "import_logs", boom)
    collector, _ = make(batches=[s.wrap(s.service_crash(101))])
    row = setting(session, collector, last_record_id=100)
    with pytest.raises(RuntimeError):
        collector.poll(session, row)
    assert row.last_record_id == 100


def test_bookmark_survives_restart_and_nothing_is_reimported(engine):
    factory = lambda: Session(engine, expire_on_commit=False)  # noqa: E731
    first, _ = make(batches=[s.wrap(s.service_crash(101), s.service_crash(102))])
    m1 = CollectorManager([first], factory, access_ttl=0)
    m1.set_enabled(first.id, True)
    with factory() as session:
        session.get(CollectorSettingRow, first.id).last_record_id = 100
        session.commit()
    assert m1.poll_once() == 2
    second, fake2 = make(batches=[])  # a restarted app: new collector, new manager, same database
    m2 = CollectorManager([second], factory, access_ttl=0)
    assert m2.poll_once() == 0
    assert fake2.queries == ["*[System[(EventID=7031 or EventID=7034 or EventID=7045 or EventID=104) and (EventRecordID>102)]]"]
    with factory() as session:
        assert event_count(session) == 2


def test_re_reading_the_same_records_adds_no_duplicates(session):
    batch = s.wrap(s.service_crash(101), s.service_crash(102))
    collector, _ = make(batches=[batch, batch])
    row = setting(session, collector, last_record_id=100)
    collector.poll(session, row)
    row.last_record_id = 100  # simulate a crash between the import and saving the bookmark
    collector.poll(session, row)
    assert event_count(session) == 2


def test_nonzero_exit_empty_output_and_timeout_are_handled(session):
    collector, _ = make(poll_rc=5)
    row = setting(session, collector, last_record_id=1)
    with pytest.raises(CollectorError, match="exited with code 5"):
        collector.poll(session, row)
    empty, _ = make(batches=[""])
    assert empty.poll(session, CollectorSettingRow(id="x", last_record_id=1)) == 0

    def slow(args):
        raise TimeoutError("wevtutil timed out")
    with pytest.raises(CollectorError, match="timed out"):
        WindowsEventLogCollector("System", runner=slow).poll(session, CollectorSettingRow(id="y", last_record_id=1))


def test_malformed_output_is_an_error_not_a_crash(session):
    collector, _ = make(batches=["<Event><oops>"])
    with pytest.raises(CollectorError):
        collector.poll(session, CollectorSettingRow(id="z", last_record_id=1))


def test_a_failed_logon_burst_raises_an_alert_end_to_end(session):
    burst = [s.logon_failure(200 + i, user="admin", ip="203.0.113.7", when=f"2026-11-23T14:20:{10 + i:02d}")
             for i in range(8)]
    collector, _ = make("Security", batches=[s.wrap(*burst)])
    row = setting(session, collector, last_record_id=199)
    assert collector.poll(session, row) == 8
    alerts, _ = AlertRepository(session).list(rule_id="HZ-001")
    assert alerts and alerts[0].source_ip == "203.0.113.7" and alerts[0].username == "admin"


def test_ids_and_descriptions_are_plain_language():
    for channel in CHANNELS:
        c = WindowsEventLogCollector(channel)
        assert c.id == f"windows-{channel.lower()}" and c.platform == "windows"
        assert c.name and len(c.description) > 20


@pytest.mark.skipif(sys.platform != "win32" or os.environ.get("HORIZON_REAL_EVENTLOG_TESTS") != "1",
                    reason="opt-in: reads the real System log of this machine (structure only)")
def test_real_system_channel_is_readable_structure_only(session):
    collector = WindowsEventLogCollector("System")
    assert collector.access() == READY
    row = setting(session, collector)
    collector.poll(session, row)  # first poll: just finds the newest record
    assert isinstance(row.last_record_id, int) and row.last_record_id > 0
