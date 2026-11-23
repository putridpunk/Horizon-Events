from datetime import datetime

from app.processors.normalizer import normalize
from app.processors.parser import parse_app_line, parse_json_record, parse_linux_auth, parse_syslog, parse_windows_record

NOW = datetime(2026, 11, 23, 15, 0, 0)


def _auth(msg):
    return normalize(parse_linux_auth(f"Nov 23 14:20:31 server {msg}", NOW), "linux_auth")


def test_failed_password():
    e = _auth("sshd[1234]: Failed password for admin from 192.168.1.15 port 22 ssh2")
    assert (e.event_type.value, e.severity.value, e.username, e.source_ip) == (
        "authentication_failure", "medium", "admin", "192.168.1.15")
    assert e.timestamp.isoformat() == "2026-11-23T14:20:31"


def test_unknown_user():
    e = _auth("sshd[1]: Failed password for invalid user ghost from 10.0.0.9 port 22 ssh2")
    assert (e.event_type.value, e.username) == ("unknown_user", "ghost")


def test_accepted():
    e = _auth("sshd[1]: Accepted password for alice from 10.0.0.5 port 22 ssh2")
    assert (e.event_type.value, e.severity.value) == ("authentication_success", "low")


def test_sudo():
    e = _auth("sudo: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash")
    assert (e.event_type.value, e.severity.value, e.username) == ("privilege_escalation", "high", "bob")


def test_lockout():
    e = _auth("pam_tally2(sshd:auth): user admin (locked) tally 5")
    assert (e.event_type.value, e.username) == ("account_lockout", "admin")


def test_syslog_service_failure():
    p = parse_syslog("Nov 23 14:00:00 srv systemd[1]: nginx.service: Failed with result 'exit-code'.", NOW)
    e = normalize(p, "linux_syslog")
    assert (e.event_type.value, e.service) == ("service_failure", "nginx")


def test_year_rollover():
    p = parse_linux_auth("Dec 31 23:59:00 s sshd[1]: Failed password for a from 1.2.3.4", datetime(2027, 1, 2))
    assert p["timestamp"].year == 2026


def test_garbage_returns_none():
    assert parse_linux_auth("not a log line", NOW) is None
    assert parse_syslog("\x00\x01garbage", NOW) is None
    assert parse_app_line("???") is None
    assert parse_json_record({"no": "timestamp"}) is None
    assert parse_windows_record({"EventID": "4625"}) is None


def test_windows_event_ids():
    def ev(eid, **kw):
        return normalize(parse_windows_record({"EventID": eid, "TimeCreated": "2026-11-23T10:00:00Z", **kw}), "windows")
    assert ev("4625", TargetUserName="x", IpAddress="1.2.3.4").event_type.value == "authentication_failure"
    assert ev("4624").event_type.value == "authentication_success"
    assert ev("4740", TargetUserName="x").event_type.value == "account_lockout"
    assert ev("4672").event_type.value == "privilege_escalation"
    assert ev("4728").event_type.value == "privilege_escalation"
    assert ev("7031", ServiceName="Spooler").event_type.value == "service_failure"
    assert ev("4625", SubStatus="0xC0000064").event_type.value == "unknown_user"


def test_app_line():
    e = normalize(parse_app_line("2026-11-23 10:15:02 ERROR [payments] gateway timeout"), "application")
    assert (e.event_type.value, e.service) == ("service_failure", "payments")
