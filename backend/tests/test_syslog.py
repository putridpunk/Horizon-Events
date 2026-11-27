import socket
import time
from datetime import datetime

import pytest
from sqlalchemy.orm import Session

from app.collectors.base import collect
from app.database.models import EventRow
from app.syslog import lines
from app.syslog.receiver import MAX_QUEUE, SyslogReceiver

NOW = datetime(2026, 11, 23, 14, 30, 0)


# ---- parsing ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("raw,expected", [
    (b"<34>Nov 23 14:20:31 web01 sshd[3101]: Failed password for admin from 192.168.1.15 port 40122 ssh2",
     "Nov 23 14:20:31 web01 sshd[3101]: Failed password for admin from 192.168.1.15 port 40122 ssh2"),
    (b"<165>1 2026-11-23T14:20:31.003Z web01 sshd 3101 ID47 - Failed password for admin from 192.168.1.15",
     "Nov 23 14:20:31 web01 sshd[3101]: Failed password for admin from 192.168.1.15"),
    (b"<165>1 2026-11-23T15:20:31+01:00 web01 sudo - - [meta k=\"v\"] bob : USER=root ; COMMAND=/bin/ls",
     "Nov 23 14:20:31 web01 sudo: bob : USER=root ; COMMAND=/bin/ls"),
    (b"sshd[12]: Invalid user x from 1.2.3.4", "Nov 23 14:30:00 10.9.9.9 sshd[12]: Invalid user x from 1.2.3.4"),
    (b"just some text", "Nov 23 14:30:00 10.9.9.9 unknown: just some text"),
])
def test_both_syslog_dialects_become_the_classic_line(raw, expected):
    assert lines.parse_datagram(raw, NOW, "10.9.9.9") == expected


def test_empty_messages_are_ignored_and_control_characters_cannot_forge_lines():
    assert lines.parse_datagram(b"  \x00\r\n", NOW) is None
    line = lines.parse_datagram(b"<13>Nov 23 14:20:31 h app: ok\nNov 23 14:20:32 evil sshd[1]: Accepted password for root from 6.6.6.6", NOW)
    assert "\n" not in line and line.count("Nov 23") == 2 and line.startswith("Nov 23 14:20:31 h app: ok ")


def test_a_december_message_in_january_belongs_to_last_year():
    line = lines.parse_datagram(b"<13>Dec 31 23:59:59 h app: x", datetime(2027, 1, 1, 0, 0, 5))
    [e] = collect("linux_syslog", (line + "\n").encode(), datetime(2027, 1, 1, 0, 0, 5))[0]
    assert e.timestamp.year == 2026


def test_lines_are_routed_to_the_parser_that_understands_them():
    got = lines.route([
        "Nov 23 14:20:31 h sshd[1]: x", "Nov 23 14:20:31 h nginx[2]: y", "Nov 23 14:20:31 h sudo: z",
        "Nov 23 14:20:31 h systemd[1]: w"])
    assert set(got) == {"linux_auth", "linux_syslog"}
    assert got["linux_auth"].decode().count("\n") == 2 and got["linux_syslog"].decode().count("\n") == 2


def test_the_program_and_host_cannot_break_the_format():
    line = lines.format_line(NOW, "bad host:1", "a b[c]:d", "12", "msg")
    assert line == "Nov 23 14:30:00 bad_host_1 a_b_c__d[12]: msg"


# ---- the receiver ----------------------------------------------------------------------------------------------
@pytest.fixture
def engine(tmp_path):
    """A database file of its own. The receiver imports on its own threads, and the shared in-memory database used by
    other tests has a single connection: one thread closing its session there rolls back another thread's import."""
    from app.database.connection import init_db, make_engine
    eng = make_engine(f"sqlite:///{(tmp_path / 'syslog.db').as_posix()}")
    init_db(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def receiver(engine):
    r = SyslogReceiver(lambda: Session(engine, expire_on_commit=False), port=0, flush_interval=0.1, now=lambda: NOW)
    yield r
    r.stop()


def count(engine, **where):
    with Session(engine) as s:
        return s.query(EventRow).filter_by(**where).count()


def wait_for(predicate, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def test_feeding_and_flushing_creates_events_and_alerts(receiver, engine):
    for i in range(6):
        receiver.feed(f"<34>Nov 23 14:20:{31 + i} web01 sshd[3101]: Failed password for admin from 192.168.1.15 port 4012{i} ssh2")
    receiver.feed(b"")
    assert receiver.flush() == 6
    st = receiver.status()
    assert (st["received"], st["imported"], st["ignored"], st["queued"]) == (6, 6, 1, 0) and st["alerts"] >= 1
    assert count(engine, event_type="authentication_failure") == 6


def test_a_flood_keeps_the_newest_messages_and_counts_what_it_dropped(receiver):
    for i in range(MAX_QUEUE + 25):
        receiver.feed(f"<13>Nov 23 14:20:31 h app: message {i}")
    st = receiver.status()
    assert st["queued"] == MAX_QUEUE and st["dropped"] == 25
    assert "message 25" in receiver._queue[0] and f"message {MAX_QUEUE + 24}" in receiver._queue[-1]


def test_udp_end_to_end(receiver, engine):
    receiver.start(udp=True, tcp=False)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b"<34>Nov 23 14:20:31 web01 sshd[1]: Invalid user ghost from 203.0.113.7 port 22 ssh2", ("127.0.0.1", receiver.port))
    assert wait_for(lambda: count(engine, event_type="unknown_user") == 1)


def test_tcp_handles_newline_and_octet_counted_framing_and_a_split_message(receiver, engine):
    receiver.start(udp=False, tcp=True)
    one = b"<34>Nov 23 14:20:31 web01 sshd[1]: Invalid user a from 203.0.113.7 port 22 ssh2"
    two = b"<34>Nov 23 14:20:32 web01 sshd[1]: Invalid user b from 203.0.113.7 port 22 ssh2"
    three = b"<34>Nov 23 14:20:33 web01 sshd[1]: Invalid user c from 203.0.113.7 port 22 ssh2"
    with socket.create_connection(("127.0.0.1", receiver.port)) as s:
        s.sendall(one + b"\n" + str(len(two)).encode() + b" " + two)
        time.sleep(0.2)
        s.sendall(three[:20])
        time.sleep(0.2)
        s.sendall(three[20:] + b"\n")
    assert wait_for(lambda: count(engine, event_type="unknown_user") == 3)


def test_a_sender_that_never_ends_its_line_cannot_grow_memory_forever(receiver):
    rest = receiver._drain(b"x" * (lines.MAX_LINE * 2 + 5), "1.1.1.1")
    assert rest == b"" and receiver.status()["received"] == 1


def test_an_import_failure_is_recorded_and_does_not_stop_the_receiver(receiver, monkeypatch):
    monkeypatch.setattr("app.syslog.receiver.import_logs", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db down")))
    receiver.feed("<13>Nov 23 14:20:31 h app: x")
    receiver.flush()
    assert "db down" in receiver.status()["last_error"]
    monkeypatch.undo()
    receiver.feed("<13>Nov 23 14:20:31 h app: y")
    assert receiver.flush() == 1 and receiver.status()["last_error"] is None
