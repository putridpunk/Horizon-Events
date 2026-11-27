import json
import time

import pytest

from app.database.collector_models import CollectorSettingRow
from app.database.models import EventRow
from app.system import os_logs
from app.system.base import NEEDS_PERMISSION, READY, UNAVAILABLE
from app.system.os_logs import JournaldCollector, MacLogCollector
from app.system.registry import platform_name


def micro(iso: str) -> int:
    from datetime import datetime, timezone
    return int(datetime.fromisoformat(iso).replace(tzinfo=timezone.utc).timestamp() * 1_000_000)


def journal(*entries):
    return "\n".join(json.dumps(e) for e in entries)


def entry(at: str, message, ident="sshd", pid="3101", host="web01"):
    return {"__REALTIME_TIMESTAMP": str(micro(at)), "MESSAGE": message, "SYSLOG_IDENTIFIER": ident, "_PID": pid,
            "_HOSTNAME": host}


class Runner:
    def __init__(self, output="", rc=0, error=None):
        self.output, self.rc, self.error, self.calls = output, rc, error, []

    def __call__(self, args):
        self.calls.append(args)
        if self.error:
            raise self.error
        return self.rc, self.output


@pytest.fixture
def setting(session):
    row = CollectorSettingRow(id="x")
    session.add(row)
    session.flush()
    return row


def events(session):
    return session.query(EventRow).order_by(EventRow.timestamp).all()


# ---- journald --------------------------------------------------------------------------------------------------
def test_journald_access_states():
    assert JournaldCollector(Runner(), tool=lambda n: None).access() == UNAVAILABLE
    assert JournaldCollector(Runner(rc=0), tool=lambda n: "/bin/journalctl").access() == READY
    assert JournaldCollector(Runner(rc=1), tool=lambda n: "/bin/journalctl").access() == NEEDS_PERMISSION
    assert JournaldCollector(Runner(error=OSError()), tool=lambda n: "/bin/journalctl").access() == UNAVAILABLE


def test_the_first_poll_only_follows_from_now(session, setting):
    runner = Runner(journal(entry("2026-11-23T14:20:31", "old")))
    c = JournaldCollector(runner)
    assert c.poll(session, setting) == 0 and runner.calls == []
    assert abs(setting.last_record_id - time.time() * 1e6) < 5e6


def test_backfill_reads_history_once(session, setting):
    setting.backfill_hours = 24
    now = int(time.time() * 1_000_000)
    line = {"__REALTIME_TIMESTAMP": str(now - 3_600_000_000), "MESSAGE": "Failed password for admin from 192.168.1.15 port 22 ssh2",
            "SYSLOG_IDENTIFIER": "sshd", "_PID": "1", "_HOSTNAME": "web01"}
    runner = Runner(json.dumps(line))
    assert JournaldCollector(runner).poll(session, setting) == 1
    assert setting.backfill_hours is None and setting.last_record_id == now - 3_600_000_000
    assert runner.calls[0][:3] == ["journalctl", "-o", "json"] and "--since" in runner.calls[0]


def test_entries_become_events_and_the_bookmark_advances(session, setting):
    start = micro("2026-11-23T14:00:00")
    setting.last_record_id = start
    out = journal(
        entry("2026-11-23T14:20:31", "Failed password for admin from 192.168.1.15 port 40122 ssh2"),
        entry("2026-11-23T14:20:32", "Failed password for admin from 192.168.1.15 port 40124 ssh2"),
        entry("2026-11-23T13:59:59", "before the bookmark"),
        entry("2026-11-23T14:21:00", "nginx.service: Failed with result 'exit-code'.", ident="systemd", pid="1"),
        {"__REALTIME_TIMESTAMP": str(micro("2026-11-23T14:22:00")), "MESSAGE": [1, 2, 3], "SYSLOG_IDENTIFIER": "x"},
        {"MESSAGE": "no timestamp"}, "not json")
    c = JournaldCollector(Runner(out.replace('"not json"', "not json")))
    assert c.poll(session, setting) == 3
    types = [e.event_type for e in events(session)]
    assert types.count("authentication_failure") == 2 and "service_failure" in types
    assert setting.last_record_id == micro("2026-11-23T14:22:00")  # the newest entry seen, even the unreadable one
    # the same output again adds nothing: every entry is at or before the bookmark
    assert JournaldCollector(Runner(out)).poll(session, setting) == 0


def test_a_failing_tool_raises_and_keeps_the_bookmark(session, setting):
    setting.last_record_id = 123
    with pytest.raises(RuntimeError, match="exited with code 1"):
        JournaldCollector(Runner(rc=1)).poll(session, setting)
    with pytest.raises(RuntimeError, match="could not run"):
        JournaldCollector(Runner(error=OSError("gone"))).poll(session, setting)
    assert setting.last_record_id == 123


# ---- macOS -----------------------------------------------------------------------------------------------------
def mac(at: str, message, path="/usr/sbin/sshd", pid=412):
    return json.dumps({"timestamp": at, "eventMessage": message, "processImagePath": path, "processID": pid})


def test_mac_access_states():
    assert MacLogCollector(Runner(), tool=lambda n: None).access() == UNAVAILABLE
    assert MacLogCollector(Runner(rc=0), tool=lambda n: "/usr/bin/log").access() == READY
    assert MacLogCollector(Runner(rc=1), tool=lambda n: "/usr/bin/log").access() == NEEDS_PERMISSION


def test_mac_entries_become_events(session, setting):
    setting.last_record_id = micro("2026-11-23T14:00:00")
    out = "\n".join([
        mac("2026-11-23 14:20:31.123456+0000", "Failed password for admin from 192.168.1.15 port 40122 ssh2"),
        mac("2026-11-23 14:20:32.000000+0000", "Invalid user ghost from 203.0.113.7 port 22"),
        mac("2026-11-23 13:00:00.000000+0000", "too old"),
        mac("2026-11-23 15:20:33.000000+0100", "Accepted publickey for deploy from 10.0.0.21 port 22 ssh2"),  # 14:20:33 UTC
        "garbage"])
    runner = Runner(out)
    assert MacLogCollector(runner).poll(session, setting) == 4 - 1
    got = {e.event_type for e in events(session)}
    assert {"authentication_failure", "unknown_user", "authentication_success"} <= got
    assert setting.last_record_id == micro("2026-11-23T14:20:33")
    call = runner.calls[0]
    assert call[:3] == ["log", "show", "--style"] and "--predicate" in call and 'process == "sshd"' in call[call.index("--predicate") + 1]


def test_mac_reads_the_oldest_entries_first_when_there_are_too_many(session, setting, monkeypatch):
    monkeypatch.setattr(os_logs, "MAX_ENTRIES", 2)
    setting.last_record_id = micro("2026-11-23T14:00:00")
    out = "\n".join(mac(f"2026-11-23 14:20:3{i}.000000+0000", f"Invalid user u{i} from 203.0.113.7 port 22") for i in range(5))
    assert MacLogCollector(Runner(out)).poll(session, setting) == 2
    assert setting.last_record_id == micro("2026-11-23T14:20:31")
    assert MacLogCollector(Runner(out)).poll(session, setting) == 2  # the next two


def test_mac_platform_is_named():
    assert platform_name() in {"windows", "linux", "mac", "other"}


def test_collectors_are_registered_per_platform(monkeypatch):
    from app.system import registry
    monkeypatch.setattr(registry.sys, "platform", "darwin")
    assert [c.id for c in registry.build_collectors()] == ["mac-log"] and registry.platform_name() == "mac"
    monkeypatch.setattr(registry.sys, "platform", "linux")
    assert [c.id for c in registry.build_collectors()] == ["linux-auth", "linux-syslog", "linux-journal"]
