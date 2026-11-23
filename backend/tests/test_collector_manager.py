import time

import pytest
from sqlalchemy.orm import Session

from app.database.collector_models import CollectorSettingRow, get_setting, set_setting
from app.system.base import NEEDS_PERMISSION, READY, UNAVAILABLE, WAITING_SIGNOUT, Collector
from app.system.manager import CollectorManager


class Fake(Collector):
    platform = "windows"

    def __init__(self, id_, access=READY, imports=2, fail=False):
        self.id, self.name, self.description = id_, id_.title(), f"fake {id_}"
        self._access, self.imports, self.fail, self.polls = access, imports, fail, 0

    def access(self):
        return self._access

    def poll(self, session, setting):
        self.polls += 1
        if self.fail:
            raise RuntimeError("wevtutil exploded")
        setting.last_record_id += 10
        return self.imports


@pytest.fixture
def factory(engine):
    return lambda: Session(engine, expire_on_commit=False)


def manager(factory, *collectors, **kw):
    return CollectorManager(list(collectors), factory, access_ttl=kw.pop("access_ttl", 0), **kw)


def test_new_collectors_are_off_until_enabled(factory):
    c = Fake("system")
    m = manager(factory, c)
    assert m.poll_once() == 0 and c.polls == 0
    assert m.status()[0]["state"] == "off" and m.status()[0]["access"] == READY


def test_poll_once_runs_enabled_ready_collectors_only(factory):
    ready, denied, off = Fake("system"), Fake("security", access=NEEDS_PERMISSION), Fake("application")
    m = manager(factory, ready, denied, off)
    m.set_enabled("system", True)
    m.set_enabled("security", True)
    assert m.poll_once() == 2
    assert (ready.polls, denied.polls, off.polls) == (1, 0, 0)


def test_exception_is_recorded_and_other_collectors_continue(factory):
    bad, good = Fake("system", fail=True), Fake("application")
    m = manager(factory, bad, good)
    m.set_enabled("system", True)
    m.set_enabled("application", True)
    assert m.poll_once() == 2
    by_id = {s["id"]: s for s in m.status()}
    assert "wevtutil exploded" in by_id["system"]["last_error"] and by_id["application"]["last_error"] is None
    bad.fail = False
    m.poll_once()
    assert {s["id"]: s for s in m.status()}["system"]["last_error"] is None  # cleared by the next success


def test_failed_poll_does_not_move_the_bookmark(factory):
    c = Fake("system", fail=True)
    m = manager(factory, c)
    m.set_enabled("system", True)
    m.poll_once()
    with factory() as s:
        assert s.get(CollectorSettingRow, "system").last_record_id == 0
    c.fail = False
    m.poll_once()
    with factory() as s:
        assert s.get(CollectorSettingRow, "system").last_record_id == 10


def test_disable_stops_polling_and_enable_resumes_from_the_bookmark(factory):
    c = Fake("system")
    m = manager(factory, c)
    m.set_enabled("system", True)
    m.poll_once()
    m.set_enabled("system", False)
    m.poll_once()
    assert c.polls == 1
    m.set_enabled("system", True)
    m.poll_once()
    with factory() as s:
        assert s.get(CollectorSettingRow, "system").last_record_id == 20


def test_status_states(factory):
    cs = [Fake("a"), Fake("b", access=NEEDS_PERMISSION), Fake("c", access=WAITING_SIGNOUT), Fake("d", access=UNAVAILABLE)]
    m = manager(factory, *cs)
    for c in cs:
        m.set_enabled(c.id, True)
    m.poll_once()
    assert {s["id"]: s["state"] for s in m.status()} == {
        "a": "collecting", "b": "needs_permission", "c": "waiting_signout", "d": "unavailable"}


def test_status_counts_events_and_last_activity(factory):
    m = manager(factory, Fake("system", imports=3))
    m.set_enabled("system", True)
    m.poll_once()
    m.poll_once()
    s = m.status()[0]
    assert s["events_read"] == 6 and s["last_activity"]


def test_settings_survive_a_new_manager(factory):
    m1 = manager(factory, Fake("system"))
    m1.set_enabled("system", True, backfill_hours=24)
    m2 = manager(factory, Fake("system"))
    assert m2.status()[0]["enabled"] is True
    with factory() as s:
        assert s.get(CollectorSettingRow, "system").backfill_hours == 24


def test_access_is_cached_until_check_refreshes_it(factory):
    c = Fake("security", access=NEEDS_PERMISSION)
    m = manager(factory, c, access_ttl=60)
    assert m.status()[0]["access"] == NEEDS_PERMISSION
    c._access = READY
    assert m.status()[0]["access"] == NEEDS_PERMISSION  # still cached
    assert m.check("security")["access"] == READY and m.status()[0]["access"] == READY


def test_a_buggy_access_probe_reports_unavailable_without_raising(factory):
    c = Fake("system")
    c.access = lambda: 1 / 0
    assert manager(factory, c).status()[0]["access"] == UNAVAILABLE


def test_unknown_collector_raises_keyerror(factory):
    m = manager(factory, Fake("system"))
    with pytest.raises(KeyError):
        m.set_enabled("nope", True)
    with pytest.raises(KeyError):
        m.check("nope")


def test_pause_and_resume(factory):
    c = Fake("system")
    m = manager(factory, c)
    m.set_enabled("system", True)
    m.pause()
    assert m.poll_once() == 0 and c.polls == 0
    m.resume()
    assert m.poll_once() == 2


def test_thread_start_and_stop(factory):
    c = Fake("system")
    m = manager(factory, c, interval=0.05)
    m.set_enabled("system", True)
    m.start()
    try:
        assert m.running
        deadline = time.time() + 5
        while time.time() < deadline and c.polls < 2:
            time.sleep(0.05)
        assert c.polls >= 2
    finally:
        m.stop()
    assert not m.running


def test_app_settings_roundtrip(session):
    assert get_setting(session, "setup_completed", "false") == "false"
    set_setting(session, "setup_completed", "true")
    assert get_setting(session, "setup_completed") == "true"
    set_setting(session, "setup_completed", "false")
    assert get_setting(session, "setup_completed") == "false"
