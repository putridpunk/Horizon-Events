from app.collectors.base import collect
from tests import eventlog_samples as s


def parse(*events):
    found, result = collect("windows", s.wrap(*events).encode("utf-8"))
    assert result.skipped == 0, result
    return found


def test_failed_logon_fields():
    [e] = parse(s.logon_failure(1, user="admin", ip="203.0.113.7"))
    assert (e.event_type.value, e.severity.value, e.username, e.source_ip) == (
        "authentication_failure", "medium", "admin", "203.0.113.7")
    assert e.timestamp.isoformat() == "2026-11-23T14:20:31.123456" and e.host == "WS-DEMO"
    assert "Failed logon" in e.message


def test_unknown_account_substatus():
    [e] = parse(s.logon_failure(2, user="ghost", sub_status="0xc0000064"))
    assert e.event_type.value == "unknown_user" and e.username == "ghost"


def test_interactive_logon_success_has_no_ip():
    [e] = parse(s.logon_success(3, user="alice", ip="-"))
    assert (e.event_type.value, e.username, e.source_ip) == ("authentication_success", "alice", None)


def test_lockout_user_is_the_locked_account_not_the_computer():
    [e] = parse(s.lockout(4, user="bob"))
    assert (e.event_type.value, e.username) == ("account_lockout", "bob")


def test_privileged_group_change_uses_the_person_who_made_it():
    for record, event_id in enumerate((4728, 4732, 4756), start=5):
        [e] = parse(s.group_change(record, event_id=event_id, who="carol", group="Administrators"))
        assert (e.event_type.value, e.username) == ("privilege_escalation", "carol"), event_id


def test_account_created_is_recorded_as_generic():
    [e] = parse(s.event_xml("Security", 4720, 9, data={"TargetUserName": "newuser", "SubjectUserName": "carol"}))
    assert e.event_type.value == "generic" and "newuser" in e.raw


def test_system_service_crash_names_the_service():
    for record, event_id in enumerate((7031, 7034), start=10):
        [e] = parse(s.service_crash(record, service="Spooler", event_id=event_id))
        assert (e.event_type.value, e.service) == ("service_failure", "Spooler")


def test_application_crash_uses_the_first_unnamed_data_as_service():
    [e] = parse(s.app_crash(12, app="chrome.exe"))
    assert (e.event_type.value, e.service) == ("service_failure", "chrome.exe")


def test_record_id_makes_identical_looking_events_distinct():
    a, b = parse(s.logon_failure(100), s.logon_failure(101))  # same second, same user, same address
    assert a.fingerprint() != b.fingerprint()
    assert "EventRecordID=100" in a.raw and "Channel=Security" in a.raw


def test_special_and_non_ascii_characters_roundtrip():
    [e] = parse(s.logon_failure(20, user="O'Brien & <Co> João"))
    assert e.username == "O'Brien & <Co> João"


def test_seven_digit_fractional_seconds_are_accepted():
    [e] = parse(s.logon_success(21, when="2026-11-23T23:59:59"))
    assert e.timestamp.hour == 23 and e.timestamp.second == 59


def test_sample_windows_file_still_parses():
    from pathlib import Path
    sample = Path(__file__).resolve().parents[2] / "sample_logs" / "windows_events.xml"
    found, result = collect("windows", sample.read_bytes())
    assert result.imported == 7 and result.skipped == 0
    assert {e.event_type.value for e in found} >= {"authentication_failure", "account_lockout", "privilege_escalation"}
