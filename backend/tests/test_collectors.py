import pytest

from app.collectors.base import collect

GOOD = (b"Nov 23 14:20:31 s sshd[1]: Failed password for a from 1.1.1.1 port 1\n"
        b"Nov 23 14:20:32 s sshd[1]: Accepted password for b from 1.1.1.2 port 1\n"
        b"Nov 23 14:20:33 s sudo: c : TTY=x ; USER=root ; COMMAND=/bin/sh\n")


def test_linux_auth_counts():
    ev, r = collect("linux_auth", GOOD + b"garbage line\n")
    assert (r.total, r.imported, r.skipped, len(ev)) == (4, 3, 1, 3)


def test_empty_content_returns_zero():
    ev, r = collect("linux_auth", b"")
    assert (r.total, r.imported, r.skipped, ev) == (0, 0, 0, [])


def test_blank_lines_ignored():
    _, r = collect("linux_auth", b"\n\n   \n" + GOOD)
    assert r.total == 3


def test_windows_xml_csv_json():
    xml = (b'<Events><Event><System><EventID>4625</EventID><TimeCreated SystemTime="2026-11-23T10:00:00Z"/>'
           b'<Computer>WS1</Computer></System><EventData><Data Name="TargetUserName">bob</Data>'
           b'<Data Name="IpAddress">10.1.1.1</Data></EventData></Event></Events>')
    ev, r = collect("windows", xml)
    assert r.imported == 1 and ev[0].username == "bob" and ev[0].source_ip == "10.1.1.1"
    csv_ = b"EventID,TimeCreated,TargetUserName\n4740,2026-11-23T10:00:00Z,bob\n"
    assert collect("windows", csv_)[0][0].event_type.value == "account_lockout"
    js = b'[{"EventID": 4624, "TimeCreated": "2026-11-23T10:00:00Z"}]'
    assert collect("windows", js)[1].imported == 1


def test_json_array_and_jsonl():
    arr = b'[{"timestamp": "2026-11-23T10:00:00", "event_type": "service_failure", "service": "x", "message": "m"}]'
    assert collect("json", arr)[0][0].event_type.value == "service_failure"
    jl = b'{"timestamp": "2026-11-23T10:00:00"}\nnot json\n'
    r = collect("json", jl)[1]
    assert (r.imported, r.skipped) == (1, 1)


def test_unknown_source_type_raises():
    with pytest.raises(ValueError):
        collect("nope", b"x")


def test_malicious_xml_rejected():
    bomb = b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><Events>&b;</Events>'
    ev, r = collect("windows", bomb)
    assert ev == [] and r.skipped == 1


def test_binary_garbage_does_not_crash():
    for t in ("linux_auth", "linux_syslog", "windows", "application", "json"):
        ev, r = collect(t, bytes(range(256)) * 4)
        assert r.imported == 0
