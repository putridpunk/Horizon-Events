import os
import subprocess
import sys

import pytest

from app.system import access
from app.system.base import NEEDS_PERMISSION, READY, UNAVAILABLE, WAITING_SIGNOUT

SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
OTHER = "S-1-5-21-1111111111-2222222222-3333333333-1002"
GROUP = access.SECURITY_READERS_SID


def runner_returning(output, rc=0):
    calls = []

    def run(args, timeout=20.0):
        calls.append(args)
        return rc, output
    run.calls = calls
    return run


# -- the command that changes a group --------------------------------------------------------
def test_the_group_is_identified_by_its_well_known_sid_not_a_translated_name():
    assert GROUP == "S-1-5-32-573"


def test_enable_command_exact_string():
    cmd = access.enable_command(SID)
    assert os.path.basename(cmd[0]).lower() == "powershell.exe"
    assert cmd[1:-1] == ["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command"]
    assert cmd[-1] == f"Add-LocalGroupMember -SID {GROUP} -Member {SID}"


@pytest.mark.parametrize("bad", ["", "admin", "WS\\alice", f"{SID}; calc", f"{SID}' ; calc ; '", "$(calc)",
                                 f"{SID}\n", f" {SID}", "S-1-5-21", "S-1-5-21-1-2-3-x", None, 12345])
def test_enable_command_rejects_anything_that_is_not_a_plain_sid(bad):
    with pytest.raises(ValueError):
        access.enable_command(bad)


def test_request_elevation_asks_windows_for_its_permission_prompt_and_runs_nothing_itself(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    seen = {}

    def fake_shell(hwnd, verb, file, params, cwd, show):
        seen.update(hwnd=hwnd, verb=verb, file=file, params=params, show=show)
        return 42  # > 32 means the request was accepted

    def forbidden(*a, **k):
        raise AssertionError("the elevation command must never be executed by the code under test")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert access.request_elevation(access.enable_command(SID), shell=fake_shell) is True
    assert seen["verb"] == "runas" and seen["file"].lower().endswith("powershell.exe") and seen["show"] == 0
    assert f"Add-LocalGroupMember -SID {GROUP} -Member {SID}" in seen["params"]


def test_request_elevation_reports_a_declined_prompt(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert access.request_elevation(access.enable_command(SID), shell=lambda *a: 5) is False


def test_request_elevation_is_not_available_off_windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    assert access.request_elevation(access.enable_command(SID), shell=lambda *a: 99) is False


# -- reading the current state (no changes) --------------------------------------------------
def test_current_user_sid_parses_the_csv_from_whoami():
    assert access.current_user_sid(runner_returning(f'"WS-DEMO\\alice","{SID}"\r\n')) == SID
    assert access.current_user_sid(runner_returning(f'"Utilizador\\joão","{SID}"')) == SID


@pytest.mark.parametrize("rc,out", [(1, ""), (0, ""), (0, "garbage"), (0, '"a","not-a-sid"')])
def test_current_user_sid_returns_none_when_unreadable(rc, out):
    assert access.current_user_sid(runner_returning(out, rc)) is None


def test_current_user_sid_survives_a_missing_tool():
    def missing(args, timeout=20.0):
        raise FileNotFoundError("whoami")
    assert access.current_user_sid(missing) is None


def test_is_member_matches_by_sid_whatever_the_language():
    assert access.is_member(SID, runner_returning(f"{OTHER}\r\n{SID}\r\n")) is True
    assert access.is_member(SID, runner_returning(f"{OTHER}\r\n")) is False
    assert access.is_member(SID, runner_returning("", rc=1)) is False


def test_token_has_group_reads_sids_from_whoami_groups():
    csv_out = ('"Todos","Grupo bem conhecido","S-1-1-0","Obrigatório"\r\n'
               f'"BUILTIN\\Leitores de Registo de Eventos","Alias","{GROUP}","Obrigatório"\r\n')
    assert access.token_has_group(runner_returning(csv_out)) is True
    assert access.token_has_group(runner_returning('"Everyone","Well-known group","S-1-1-0","x"\r\n')) is False
    assert access.token_has_group(runner_returning("", rc=1)) is False


@pytest.mark.parametrize("probe,member,in_token,expected", [
    (READY, False, False, READY), (READY, True, True, READY),
    (NEEDS_PERMISSION, False, False, NEEDS_PERMISSION),
    (NEEDS_PERMISSION, True, False, WAITING_SIGNOUT),
    (NEEDS_PERMISSION, True, True, NEEDS_PERMISSION),
    (UNAVAILABLE, True, False, UNAVAILABLE), (UNAVAILABLE, False, False, UNAVAILABLE)])
def test_state_matrix(probe, member, in_token, expected):
    assert access.security_state(probe, member, in_token) == expected


def test_refine_only_runs_helper_tools_when_access_was_denied():
    def run(args, timeout=20.0):
        run.calls.append(os.path.basename(args[0]).lower())
        return 0, (f"{SID}" if "powershell" in args[0].lower() else
                   (f'"WS\\a","{SID}"' if "/user" in args else f'"x","y","{OTHER}","z"'))
    run.calls = []
    refine = access.make_security_refine(run)
    assert refine(READY) == READY and refine(UNAVAILABLE) == UNAVAILABLE and run.calls == []
    assert refine(NEEDS_PERMISSION) == WAITING_SIGNOUT  # a member, but the group is not in the token yet
    assert run.calls  # it did have to look


def test_refine_without_a_known_user_falls_back_to_needs_permission():
    refine = access.make_security_refine(runner_returning("", rc=1))
    assert refine(NEEDS_PERMISSION) == NEEDS_PERMISSION


@pytest.mark.skipif(sys.platform != "win32" or os.environ.get("HORIZON_REAL_EVENTLOG_TESTS") != "1",
                    reason="opt-in: queries this machine's own account and group (read-only)")
def test_real_read_only_queries_have_the_expected_shape():
    sid = access.current_user_sid()
    assert sid and sid.startswith("S-1-5-")
    assert isinstance(access.is_member(sid), bool)
    assert isinstance(access.token_has_group(), bool)
