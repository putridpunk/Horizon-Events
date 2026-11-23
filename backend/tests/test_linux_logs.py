import os

import pytest

from app.database.collector_models import CollectorSettingRow
from app.database.repositories import AlertRepository, EventRepository
from app.system.base import NEEDS_PERMISSION, READY, UNAVAILABLE
from app.system.linux_logs import LinuxLogCollector, default_linux_collectors

FAIL = "Nov 23 14:20:{s:02d} web01 sshd[9]: Failed password for root from 203.0.113.9 port {s} ssh2\n"


def lines(start, n):
    return "".join(FAIL.format(s=start + i) for i in range(n))


def make(tmp_path, *names, create=("auth.log",)):
    paths = [tmp_path / n for n in names]
    for n in create:
        if not (tmp_path / n).exists():  # never truncate a log that already has lines
            (tmp_path / n).write_text("")
    return LinuxLogCollector("linux-auth", "Linux authentication log", "linux_auth", paths, "desc long enough")


def setting(session):
    row = CollectorSettingRow(id="linux-auth", enabled=True)
    session.add(row)
    session.flush()
    return row


def test_states_ready_unavailable_and_needs_permission(tmp_path, monkeypatch):
    assert make(tmp_path, "auth.log", "secure").access() == READY
    assert make(tmp_path, "nothing.log", "none2.log", create=()).access() == UNAVAILABLE
    monkeypatch.setattr(os, "access", lambda path, mode: False)  # exists but unreadable for this user
    assert make(tmp_path, "auth.log").access() == NEEDS_PERMISSION


def test_prefers_the_first_existing_path(tmp_path):
    c = make(tmp_path, "auth.log", "secure", create=("secure",))
    assert c.active_path() == tmp_path / "secure"
    (tmp_path / "auth.log").write_text("")
    assert c.active_path() == tmp_path / "auth.log"


def test_first_poll_starts_at_the_end_so_history_is_not_imported(tmp_path, session):
    c = make(tmp_path, "auth.log")
    (tmp_path / "auth.log").write_text(lines(0, 8))
    row = setting(session)
    assert c.poll(session, row) == 0
    assert EventRepository(session).search()[1] == 0 and row.last_record_id > 0


def test_new_lines_are_imported_and_raise_an_alert(tmp_path, session):
    c = make(tmp_path, "auth.log")
    path = tmp_path / "auth.log"
    row = setting(session)
    c.poll(session, row)  # first poll: follow from the end of an empty file
    with open(path, "a") as f:
        f.write(lines(0, 3))
    assert c.poll(session, row) == 3
    with open(path, "a") as f:
        f.write(lines(3, 6))
    assert c.poll(session, row) == 6
    alerts, _ = AlertRepository(session).list(rule_id="HZ-001")
    assert alerts and alerts[0].source_ip == "203.0.113.9"


def test_an_empty_file_does_not_make_the_next_poll_a_first_run_again(tmp_path, session):
    c = make(tmp_path, "auth.log")
    row = setting(session)
    c.poll(session, row)
    c.poll(session, row)
    with open(tmp_path / "auth.log", "a") as f:
        f.write(lines(0, 2))
    assert c.poll(session, row) == 2  # lines written after the first poll are not skipped


def test_bookmark_survives_a_new_collector_instance(tmp_path, session):
    path = tmp_path / "auth.log"
    row = setting(session)
    make(tmp_path, "auth.log").poll(session, row)
    with open(path, "a") as f:
        f.write(lines(0, 2))
    assert make(tmp_path, "auth.log").poll(session, row) == 2
    assert make(tmp_path, "auth.log").poll(session, row) == 0  # nothing new, nothing re-read
    assert EventRepository(session).search()[1] == 2


def test_log_rotation_restarts_from_the_top_of_the_new_file(tmp_path, session):
    c = make(tmp_path, "auth.log")
    path = tmp_path / "auth.log"
    row = setting(session)
    with open(path, "a") as f:
        f.write("x" * 500 + "\n")
    c.poll(session, row)  # follows from the end (500+ bytes in)
    path.write_text(lines(0, 2))  # rotated: a new, smaller file
    assert c.poll(session, row) == 2


def test_half_written_lines_wait_for_their_newline(tmp_path, session):
    c = make(tmp_path, "auth.log")
    path = tmp_path / "auth.log"
    row = setting(session)
    c.poll(session, row)
    with open(path, "a") as f:
        f.write(FAIL.format(s=1)[:-1])  # no newline yet
    assert c.poll(session, row) == 0
    with open(path, "a") as f:
        f.write("\n")
    assert c.poll(session, row) == 1


def test_default_collectors_cover_auth_and_syslog():
    by_id = {c.id: c for c in default_linux_collectors()}
    assert set(by_id) == {"linux-auth", "linux-syslog"}
    assert all(c.platform == "linux" and len(c.description) > 20 for c in by_id.values())
    assert by_id["linux-auth"].source_type == "linux_auth" and by_id["linux-syslog"].source_type == "linux_syslog"
