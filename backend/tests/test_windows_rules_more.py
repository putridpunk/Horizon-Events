"""HZ-013 to HZ-017: explicit-credential logons, NTLM network logons, new administrators, PowerShell and USB."""
from app.collectors.base import collect
from app.database.repositories import EventRepository
from app.detection.registry import DEFAULT_RULES
from app.detection.windows_rules import (ExplicitCredentialLogon, NewLocalAdministrator, NtlmNetworkLogon,
                                         SuspiciousPowerShell, UsbDevice)
from app.domain import Severity
from app.mitigation.advice import ADVICE
from app.mitre import RULE_TECHNIQUES
from tests import eventlog_samples as s


def events(session, *xml):
    found, result = collect("windows", s.wrap(*xml).encode("utf-8"))
    assert result.skipped == 0
    return EventRepository(session).add_many(found)


# ---- parsing ---------------------------------------------------------------------------------------------------
def test_explicit_credentials_name_the_actor_not_the_target():
    [e] = collect("windows", s.wrap(s.explicit_logon(1, who="alice", target="admin")).encode())[0]
    assert (e.event_type.value, e.username) == ("explicit_credentials", "alice") and "admin" in e.message


def test_a_type_3_ntlm_logon_is_its_own_event_but_kerberos_is_not():
    [ntlm] = collect("windows", s.wrap(s.ntlm_logon(1)).encode())[0]
    assert ntlm.event_type.value == "ntlm_logon" and ntlm.source_ip == "93.184.216.34"
    kerberos = s.event_xml("Security", 4624, 2, "2026-11-23T04:00:00", {
        "TargetUserName": "bob", "LogonType": "3", "IpAddress": "10.0.0.5", "AuthenticationPackageName": "Kerberos"})
    [k] = collect("windows", s.wrap(kerberos).encode())[0]
    assert k.event_type.value == "authentication_success"


def test_powershell_script_text_is_kept_and_truncated_in_the_message():
    script = "Invoke-Expression " + "A" * 500
    [e] = collect("windows", s.wrap(s.powershell_block(1, script)).encode())[0]
    assert e.event_type.value == "powershell_script" and e.metadata["script"] == script
    assert len(e.message) < 250


def test_usb_device_keeps_its_description():
    [e] = collect("windows", s.wrap(s.usb_device(1, "SanDisk Cruzer")).encode())[0]
    assert e.event_type.value == "usb_device" and e.metadata["device"] == "SanDisk Cruzer" and e.username is None


def test_group_change_records_the_group_name():
    [e] = collect("windows", s.wrap(s.group_change(1, group="Administrators")).encode())[0]
    assert e.metadata["group"] == "Administrators"


# ---- rules -----------------------------------------------------------------------------------------------------
def test_explicit_credentials_need_a_few_in_a_short_time(session):
    one = events(session, s.explicit_logon(1))
    assert ExplicitCredentialLogon().evaluate(one, EventRepository(session)) == []
    more = events(session, s.explicit_logon(2, when="2026-11-23T10:01:00"), s.explicit_logon(3, when="2026-11-23T10:02:00"))
    [d] = ExplicitCredentialLogon().evaluate(more, EventRepository(session))
    assert d.rule_id == "HZ-013" and d.username == "alice" and d.occurrences == 3


def test_ntlm_from_a_public_address_is_high_and_private_or_machine_accounts_are_ignored(session):
    evs = events(session, s.ntlm_logon(1), s.ntlm_logon(2, ip="10.0.0.9", when="2026-11-23T04:01:00"),
                 s.ntlm_logon(3, user="WS-DEMO$", when="2026-11-23T04:02:00"),
                 s.ntlm_logon(4, user="ANONYMOUS LOGON", when="2026-11-23T04:03:00"))
    [d] = NtlmNetworkLogon().evaluate(evs, None)
    assert d.severity is Severity.high and d.source_ip == "93.184.216.34" and d.username == "svc_backup"
    assert len(NtlmNetworkLogon(params={"ignore_private": False}).evaluate(evs, None)) == 2


def test_only_the_administrators_group_triggers_the_new_administrator_rule(session):
    evs = events(session, s.group_change(1, group="Administrators"),
                 s.group_change(2, group="Backup Operators", when="2026-11-23T13:42:00"),
                 s.group_change(3, event_id=4756, group="Domain Admins", who="dave", when="2026-11-23T13:43:00"))
    ds = {d.username: d for d in NewLocalAdministrator().evaluate(evs, None)}
    assert set(ds) == {"carol", "dave"}
    assert ds["carol"].severity is Severity.high and ds["dave"].severity is Severity.critical


def test_suspicious_powershell_matches_keywords_and_ignores_harmless_scripts(session):
    evs = events(session, s.powershell_block(1, "Get-Date"),
                 s.powershell_block(2, "powershell -EncodedCommand SQBFAFgA", when="2026-11-23T10:31:00"),
                 s.powershell_block(3, "$w = New-Object Net.WebClient; $w.DownloadString('http://x')", when="2026-11-23T10:32:00"))
    ds = SuspiciousPowerShell().evaluate(evs, None)
    assert sorted(d.description.split("'")[1] for d in ds) == ["-encodedcommand", "downloadstring"]
    assert all(d.severity is Severity.high for d in ds)
    assert SuspiciousPowerShell(params={"keywords": ["nothing-matches"]}).evaluate(evs, None) == []


def test_a_usb_device_raises_one_alert_per_device_and_can_be_ignored(session):
    evs = events(session, s.usb_device(1, "A"), s.usb_device(2, "B", when="2026-11-23T10:46:00"),
                 s.usb_device(3, "A", when="2026-11-23T10:47:00"))
    ds = UsbDevice().evaluate(evs, None)
    assert sorted(d.key for d in ds) == ["HZ-017|A|", "HZ-017|B|"] and all(d.severity is Severity.low for d in ds)
    assert len(UsbDevice(params={"ignore": ["A"]}).evaluate(evs, None)) == 1


def test_new_rules_are_registered_with_advice_and_mitre():
    ids = [f"HZ-{i:03d}" for i in range(13, 18)]
    assert set(ids) <= {r["id"] for r in DEFAULT_RULES} and set(ids) <= set(ADVICE) and set(ids) <= set(RULE_TECHNIQUES)
