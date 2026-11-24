import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.mitigation_models import MitigationRow
from app.database.models import AlertRow
from app.domain import utcnow
from app.mitigation import firewall, quarantine
from app.mitigation.advice import ADVICE, advice_for
from app.mitigation.service import MitigationError, MitigationService, load_settings, save_settings
from app.detection.registry import DEFAULT_RULES
from app.scanning.defender import THREAT, Finding, ScanOutcome
from app.scanning.service import ScanService, record_detection

PUBLIC = "8.8.4.4"
OTHER = "1.1.1.1"
LAN = "192.168.1.50"


# ---- advice ----------------------------------------------------------------------------------------------------
def test_every_rule_has_advice():
    assert {r["id"] for r in DEFAULT_RULES} <= set(ADVICE)
    assert all(ADVICE[r["id"]] for r in DEFAULT_RULES)


def test_unknown_rules_get_generic_advice():
    assert advice_for("HZ-999")


def test_the_ml_rule_advice_says_no_automatic_action():
    assert any("No automatic action" in line for line in advice_for("HZ-007"))


# ---- firewall helpers ------------------------------------------------------------------------------------------
def test_rule_name_and_arguments_use_the_parsed_address():
    assert firewall.rule_name(PUBLIC) == "Horizon Events block 8.8.4.4"
    args = firewall.add_rule_args(PUBLIC)
    assert args[:4] == ["advfirewall", "firewall", "add", "rule"]
    assert "name=Horizon Events block 8.8.4.4" in args and "remoteip=8.8.4.4" in args
    assert "dir=in" in args and "action=block" in args


@pytest.mark.parametrize("bad", ["8.8.8.8; calc", "not-an-ip", "8.8.8.8 & del", "", "1.2.3"])
def test_arguments_refuse_anything_that_is_not_an_address(bad):
    with pytest.raises(ValueError):
        firewall.add_rule_args(bad)


@pytest.mark.parametrize("ip,expected", [
    (PUBLIC, None), ("2606:4700:4700::1111", None),
    ("127.0.0.1", "routable"), ("0.0.0.0", "routable"), ("224.0.0.1", "routable"), ("169.254.1.1", "routable"),
    ("::1", "routable"), (LAN, "private-network"), ("10.0.0.7", "private-network"), ("203.0.113.7", "private-network"),
    (None, "no source"), ("garbage", "not a valid"),
])
def test_blockable_reason(ip, expected):
    reason = firewall.blockable_reason(ip, own=set())
    assert (reason is None) if expected is None else (expected in reason)


def test_private_addresses_can_be_allowed_by_the_user():
    assert firewall.blockable_reason(LAN, allow_private=True, own=set()) is None


def test_own_addresses_and_the_allowlist_are_never_blocked():
    assert "own addresses" in firewall.blockable_reason(PUBLIC, own={PUBLIC})
    assert "allowlist" in firewall.blockable_reason(PUBLIC, allowlist=["8.8.4.0/24"], own=set())
    assert "allowlist" in firewall.blockable_reason(PUBLIC, allowlist=[PUBLIC], own=set())
    assert firewall.blockable_reason(OTHER, allowlist=["8.8.4.0/24"], own=set()) is None


def test_allowlist_entries_must_be_addresses_or_ranges():
    with pytest.raises(ValueError, match="Not an IP"):
        firewall.parse_networks(["8.8.4.4", "banana"])


def test_rule_exists_reads_netsh_output():
    ok = lambda args, timeout: (0, "Rule Name:   Horizon Events block 8.8.4.4\n")  # noqa: E731
    none = lambda args, timeout: (1, "No rules match the specified criteria.\n")  # noqa: E731

    def broken(args, timeout):
        raise OSError("no netsh")

    assert firewall.rule_exists(PUBLIC, ok) and not firewall.rule_exists(PUBLIC, none) and not firewall.rule_exists(PUBLIC, broken)


# ---- quarantine ------------------------------------------------------------------------------------------------
def test_quarantine_moves_the_file_and_restore_puts_it_back(tmp_path):
    f = tmp_path / "bad.exe"
    f.write_bytes(b"payload")
    dest = quarantine.quarantine(str(f), tmp_path / "q", 5)
    assert not f.exists() and dest.endswith("5.quarantined") and open(dest, "rb").read() == b"payload"
    quarantine.restore(dest, str(f))
    assert f.read_bytes() == b"payload"


def test_quarantine_refuses_missing_files_and_windows_folder(tmp_path, monkeypatch):
    with pytest.raises(quarantine.QuarantineError, match="no longer there"):
        quarantine.quarantine(str(tmp_path / "gone"), tmp_path / "q", 1)
    sysroot = tmp_path / "windows"
    sysroot.mkdir()
    f = sysroot / "x.dll"
    f.write_text("x")
    monkeypatch.setenv("SystemRoot", str(sysroot))
    with pytest.raises(quarantine.QuarantineError, match="Windows folder"):
        quarantine.quarantine(str(f), tmp_path / "q", 2)
    assert f.exists()


def test_restore_never_overwrites(tmp_path):
    f = tmp_path / "a.exe"
    f.write_text("one")
    dest = quarantine.quarantine(str(f), tmp_path / "q", 3)
    f.write_text("a newer file")
    with pytest.raises(quarantine.QuarantineError, match="not overwritten"):
        quarantine.restore(dest, str(f))
    assert f.read_text() == "a newer file"


# ---- settings --------------------------------------------------------------------------------------------------
def test_settings_default_to_ask_first(session):
    s = load_settings(session)
    assert s["block_ip"] == "ask" and s["quarantine_file"] == "ask" and s["block_private"] is False


def test_settings_validation(session):
    assert save_settings(session, {"quarantine_file": "auto", "block_days": 3, "allowlist": [" 8.8.4.0/24 ", ""]})["allowlist"] == ["8.8.4.0/24"]
    assert load_settings(session)["quarantine_file"] == "auto"
    for bad in ({"block_ip": "auto"}, {"block_ip": "sometimes"}, {"block_days": 0}, {"block_days": 400}, {"block_days": True},
                {"allowlist": ["nope"]}, {"allowlist": "8.8.8.8"}, {"block_private": "yes"}, {"colour": "red"}):
        with pytest.raises(MitigationError):
            save_settings(session, bad)


# ---- the service -----------------------------------------------------------------------------------------------
class FakeFirewall:
    """Stands in for netsh: the elevator adds or removes rules, the runner reads them back."""

    def __init__(self, grant=True):
        self.rules, self.grant, self.calls = set(), grant, []

    def elevator(self, exe, args):
        self.calls.append(args)
        if not self.grant:
            return None, "Windows permission was not granted."
        name = next(a for a in args if a.startswith("name="))[5:]
        (self.rules.add if args[2] == "add" else self.rules.discard)(name)
        return 0, ""

    def runner(self, args, timeout):
        name = next(a for a in args if a.startswith("name="))[5:]
        return (0, f"Rule Name: {name}\n") if name in self.rules else (1, "No rules match the specified criteria.\n")


@pytest.fixture
def fw():
    return FakeFirewall()


@pytest.fixture
def factory(engine):
    return lambda: Session(engine, expire_on_commit=False)


@pytest.fixture
def service(factory, fw, tmp_path):
    return MitigationService(factory, tmp_path / "quarantine", elevator=fw.elevator, runner=fw.runner,
                             own_ips=lambda: {"10.9.9.9"})


def make_alert(session, rule_id="HZ-001", ip=PUBLIC, key=None):
    alert = AlertRow(rule_id=rule_id, rule_name="x", severity="high", status="OPEN", key=key or f"{rule_id}|{ip}",
                     description="d", source_ip=ip, created_at=utcnow(), last_seen=utcnow())
    session.add(alert)
    session.commit()
    return alert


def test_a_block_is_proposed_for_a_brute_force_alert(service, session):
    alert = make_alert(session)
    out = service.for_alert(session, alert)
    session.commit()
    assert [(a["kind"], a["target"], a["status"]) for a in out["actions"]] == [("block_ip", PUBLIC, "suggested")]
    assert out["skipped"] == []
    again = service.for_alert(session, alert)  # idempotent
    assert len(again["actions"]) == 1


@pytest.mark.parametrize("rule", ["HZ-002", "HZ-004", "HZ-005", "HZ-007"])
def test_no_block_is_proposed_for_other_rules_including_the_ml_rule(service, session, rule):
    assert service.for_alert(session, make_alert(session, rule))["actions"] == []


def test_unsafe_addresses_are_skipped_with_a_reason(service, session):
    out = service.for_alert(session, make_alert(session, ip=LAN))
    assert out["actions"] == [] and "private-network" in out["skipped"][0]["reason"]
    out = service.for_alert(session, make_alert(session, ip="10.9.9.9", key="k2"))
    assert "own addresses" in out["skipped"][0]["reason"] or "private" in out["skipped"][0]["reason"]


def test_nothing_is_proposed_when_the_mode_is_off(service, session):
    save_settings(session, {"block_ip": "off"})
    assert service.for_alert(session, make_alert(session))["actions"] == []


def test_approving_a_block_adds_the_rule_and_sets_an_expiry(service, session, fw):
    alert = make_alert(session)
    mid = service.for_alert(session, alert)["actions"][0]["id"]
    session.commit()
    assert service.approve(mid)["status"] == "running"
    service.wait()
    with service.session_factory() as s:
        row = s.get(MitigationRow, mid)
        assert row.status == "done" and row.expires_at > row.finished_at and "Blocked until" in row.detail["message"]
    assert fw.rules == {"Horizon Events block 8.8.4.4"}
    assert fw.calls[0][:4] == ["advfirewall", "firewall", "add", "rule"]


def test_declining_the_windows_prompt_fails_without_a_rule(factory, tmp_path, session):
    fw = FakeFirewall(grant=False)
    svc = MitigationService(factory, tmp_path / "q", elevator=fw.elevator, runner=fw.runner, own_ips=set)
    mid = svc.for_alert(session, make_alert(session))["actions"][0]["id"]
    session.commit()
    svc.approve(mid)
    svc.wait()
    with factory() as s:
        row = s.get(MitigationRow, mid)
        assert row.status == "failed" and "permission was not granted" in row.detail["message"]
    assert fw.rules == set()
    svc.approve(mid)  # a failed action can be retried
    svc.wait()


def test_undo_removes_the_block(service, session, fw):
    mid = service.for_alert(session, make_alert(session))["actions"][0]["id"]
    session.commit()
    service.approve(mid)
    service.wait()
    assert service.undo(mid)["status"] == "running"
    service.wait()
    assert service.history()[0]["status"] == "undone" and fw.rules == set()


def test_a_failed_undo_leaves_the_block_in_force(factory, tmp_path, session):
    fw = FakeFirewall()
    svc = MitigationService(factory, tmp_path / "q", elevator=fw.elevator, runner=fw.runner, own_ips=set)
    mid = svc.for_alert(session, make_alert(session))["actions"][0]["id"]
    session.commit()
    svc.approve(mid)
    svc.wait()
    fw.grant = False
    svc.undo(mid)
    svc.wait()
    row = svc.history()[0]
    assert row["status"] == "done" and "not granted" in row["message"] and fw.rules


def test_expired_blocks_are_flagged(service, session, factory):
    mid = service.for_alert(session, make_alert(session))["actions"][0]["id"]
    session.commit()
    service.approve(mid)
    service.wait()
    with factory() as s:
        from datetime import timedelta
        s.get(MitigationRow, mid).expires_at = utcnow() - timedelta(days=1)
        s.commit()
    assert service.history()[0]["expired"] is True


def test_the_same_address_is_not_proposed_again_while_blocked(service, session):
    first = make_alert(session)
    mid = service.for_alert(session, first)["actions"][0]["id"]
    session.commit()
    service.approve(mid)
    service.wait()
    second = make_alert(session, key="another")
    out = service.for_alert(session, second)
    assert out["actions"] == [] and "already blocked" in out["skipped"][0]["reason"]


def test_dismissed_proposals_stay_dismissed(service, session):
    alert = make_alert(session)
    mid = service.for_alert(session, alert)["actions"][0]["id"]
    session.commit()
    assert service.dismiss(mid)["status"] == "dismissed"
    assert [a["status"] for a in service.for_alert(session, alert)["actions"]] == ["dismissed"]
    with pytest.raises(MitigationError):
        service.approve(mid)


def test_approving_twice_or_unknown_ids_are_refused(service, session):
    mid = service.for_alert(session, make_alert(session))["actions"][0]["id"]
    session.commit()
    service.approve(mid)
    with pytest.raises(MitigationError):
        service.approve(mid)
    service.wait()
    with pytest.raises(LookupError):
        service.approve(9999)


def test_settings_changes_apply_at_approval_time(service, session):
    mid = service.for_alert(session, make_alert(session))["actions"][0]["id"]
    save_settings(session, {"allowlist": [PUBLIC]})
    session.commit()
    service.approve(mid)
    service.wait()
    row = service.history()[0]
    assert row["status"] == "failed" and "allowlist" in row["message"]


def test_actions_left_running_by_a_previous_session_are_closed(factory, fw, tmp_path, session):
    alert = make_alert(session)
    with factory() as s:
        s.add(MitigationRow(alert_id=alert.id, kind="block_ip", target=PUBLIC, status="running", created_at=utcnow(), detail={}))
        s.commit()
    svc = MitigationService(factory, tmp_path / "q", elevator=fw.elevator, runner=fw.runner)
    assert svc.history()[0]["status"] == "failed"


# ---- malware: quarantine and the scanner hook ------------------------------------------------------------------
def malware_alert(session, path, sha="ab" * 32):
    alert_id = record_detection(session, Finding("Trojan:Win32/Test", str(path)), sha)
    session.commit()
    return session.get(AlertRow, alert_id)


def test_quarantine_is_proposed_then_approved(service, session, tmp_path):
    bad = tmp_path / "evil.exe"
    bad.write_text("x")
    alert = malware_alert(session, bad)
    out = service.for_alert(session, alert)
    session.commit()
    action = out["actions"][0]
    assert (action["kind"], action["target"], action["status"]) == ("quarantine_file", str(bad), "suggested")
    service.approve(action["id"])
    service.wait()
    row = service.history()[0]
    assert row["status"] == "done" and not bad.exists()
    service.undo(action["id"])
    service.wait()
    assert service.history()[0]["status"] == "undone" and bad.read_text() == "x"


def test_a_vanished_file_is_skipped(service, session, tmp_path):
    alert = malware_alert(session, tmp_path / "gone.exe")
    out = service.for_alert(session, alert)
    assert out["actions"] == [] and "no longer there" in out["skipped"][0]["reason"]


def make_scan_service(factory, service, bad):
    scanner = lambda path: ScanOutcome(THREAT, [Finding("Trojan:Win32/Test", str(bad))])  # noqa: E731
    return ScanService(factory, scanner=scanner, mitigation=service)


def test_automatic_mode_quarantines_a_detection_during_the_scan(service, factory, session, tmp_path):
    save_settings(session, {"quarantine_file": "auto"})
    session.commit()
    bad = tmp_path / "evil.exe"
    bad.write_text("x")
    scans = make_scan_service(factory, service, bad)
    scans.start([str(bad)])
    scans.wait()
    row = service.history()[0]
    assert row["status"] == "done" and row["automatic"] is True and not bad.exists()


def test_ask_mode_only_proposes_during_the_scan(service, factory, tmp_path):
    bad = tmp_path / "evil.exe"
    bad.write_text("x")
    scans = make_scan_service(factory, service, bad)
    scans.start([str(bad)])
    scans.wait()
    assert service.history()[0]["status"] == "suggested" and bad.exists()


def test_off_mode_does_nothing_during_the_scan(service, factory, session, tmp_path):
    save_settings(session, {"quarantine_file": "off"})
    session.commit()
    bad = tmp_path / "evil.exe"
    bad.write_text("x")
    scans = make_scan_service(factory, service, bad)
    scans.start([str(bad)])
    scans.wait()
    assert service.history() == [] and bad.exists()


def test_a_mitigation_failure_never_loses_the_detection(factory, tmp_path):
    class Broken:
        def on_malware_alert(self, *a):
            raise RuntimeError("boom")

    bad = tmp_path / "evil.exe"
    bad.write_text("x")
    scans = ScanService(factory, scanner=lambda p: ScanOutcome(THREAT, [Finding("T", str(bad))]), mitigation=Broken())
    scans.start([str(bad)])
    scans.wait()
    with factory() as s:
        assert len(s.scalars(select(AlertRow)).all()) == 1
