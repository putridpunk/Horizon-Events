import os
import stat
import sys

import pytest

from app import uninstall
from app.shell import autostart
from tests.test_shell import FakeRegistry

ENGLISH = """Rule Name:                            Horizon Events block 8.8.4.4
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In

Rule Name:                            Core Networking - DNS (UDP-Out)
----------------------------------------------------------------------
"""
PORTUGUESE = """Nome da Regra:                        Horizon Events block 1.1.1.1
----------------------------------------------------------------------
Ativado:                              Sim

Nome da Regra:                        Horizon Events block 2606:4700:4700::1111
"""


class FakeFirewall:
    """netsh show rule lists the rules; the elevated script deletes them."""

    def __init__(self, ips, grant=True):
        self.ips, self.grant, self.scripts = list(ips), grant, []

    def runner(self, args, timeout):
        return 0, "".join(f"Rule Name:   Horizon Events block {ip}\n-----\n" for ip in self.ips)

    def elevator(self, exe, args):
        assert args[0] == "-f"
        with open(args[1], encoding="utf-8") as fh:
            text = fh.read()
        self.scripts.append(text)
        if not self.grant:
            return None, "Windows permission was not granted."
        self.ips = [ip for ip in self.ips if f'"Horizon Events block {ip}"' not in text]
        return 0, ""


# ---- firewall rules --------------------------------------------------------------------------------------------
def test_rules_are_found_by_name_in_any_windows_language():
    assert uninstall.find_block_rules(lambda a, timeout: (0, ENGLISH)) == ["8.8.4.4"]
    assert uninstall.find_block_rules(lambda a, timeout: (0, PORTUGUESE)) == ["1.1.1.1", "2606:4700:4700::1111"]


def test_lookalike_names_and_garbage_are_ignored():
    text = "Horizon Events blocker 1.2.3.4\nHorizon Events block banana\nHorizon Events block 999.1.1.1\nMy Horizon Events block\n"
    assert uninstall.find_block_rules(lambda a, timeout: (0, text)) == []


def test_each_address_is_listed_once():
    text = "Horizon Events block 8.8.4.4\nHorizon Events block 8.8.4.4\n"
    assert uninstall.find_block_rules(lambda a, timeout: (0, text)) == ["8.8.4.4"]


@pytest.mark.parametrize("exc", [OSError("no netsh"), TimeoutError("slow")])
def test_a_netsh_that_cannot_run_means_no_rules(exc):
    def runner(args, timeout):
        raise exc

    assert uninstall.find_block_rules(runner) == []


def test_with_no_rules_the_user_is_never_asked_for_permission(tmp_path):
    fw = FakeFirewall([])
    assert uninstall.remove_block_rules(fw.runner, fw.elevator, tmp_path) is True
    assert fw.scripts == []


def test_all_rules_are_removed_with_one_permission_prompt(tmp_path):
    fw = FakeFirewall(["8.8.4.4", "1.1.1.1", "9.9.9.9"])
    assert uninstall.remove_block_rules(fw.runner, fw.elevator, tmp_path) is True
    assert len(fw.scripts) == 1 and fw.ips == []
    assert fw.scripts[0].splitlines() == [f'advfirewall firewall delete rule name="Horizon Events block {ip}"'
                                          for ip in ("8.8.4.4", "1.1.1.1", "9.9.9.9")]
    assert list(tmp_path.iterdir()) == []  # the script is not left behind


def test_declining_the_prompt_reports_that_rules_remain(tmp_path):
    fw = FakeFirewall(["8.8.4.4"], grant=False)
    assert uninstall.remove_block_rules(fw.runner, fw.elevator, tmp_path) is False
    assert fw.ips == ["8.8.4.4"] and list(tmp_path.iterdir()) == []


# ---- data ------------------------------------------------------------------------------------------------------
def make_data(tmp_path):
    data = tmp_path / "HorizonEvents"
    (data / "webview" / "cache").mkdir(parents=True)
    (data / "quarantine").mkdir()
    (data / "horizon.db").write_bytes(b"db")
    (data / "quarantine" / "1.quarantined").write_bytes(b"x")
    (data / "webview" / "cache" / "f").write_bytes(b"y")
    return data


def test_the_whole_data_folder_is_removed(tmp_path):
    data = make_data(tmp_path)
    assert uninstall.remove_data(data) is True and not data.exists()


def test_read_only_files_do_not_stop_the_removal(tmp_path):
    data = make_data(tmp_path)
    os.chmod(data / "horizon.db", stat.S_IREAD)
    assert uninstall.remove_data(data) is True and not data.exists()


def test_a_missing_data_folder_is_fine(tmp_path):
    assert uninstall.remove_data(tmp_path / "HorizonEvents") is True


@pytest.mark.parametrize("name", ["Documents", "HorizonEvents2", "horizon", "Windows"])
def test_only_the_apps_own_folder_is_ever_deleted(tmp_path, name):
    other = tmp_path / name
    other.mkdir()
    (other / "precious.txt").write_text("keep")
    with pytest.raises(ValueError, match="refusing"):
        uninstall.remove_data(other)
    assert (other / "precious.txt").exists()


def test_files_that_are_briefly_held_are_retried(tmp_path, monkeypatch):
    data = make_data(tmp_path)
    real, calls, waits = uninstall.shutil.rmtree, {"n": 0}, []

    def flaky(path, onerror=None):
        calls["n"] += 1
        if calls["n"] < 3:
            raise PermissionError("held by the window component")
        return real(path, onerror=onerror)

    monkeypatch.setattr(uninstall.shutil, "rmtree", flaky)
    assert uninstall.remove_data(data, attempts=5, wait=0.5, sleep=waits.append) is True
    assert calls["n"] == 3 and waits == [0.5, 0.5]


def test_files_that_stay_held_are_reported_after_the_last_try(tmp_path, monkeypatch):
    data = make_data(tmp_path)
    monkeypatch.setattr(uninstall.shutil, "rmtree", lambda path, onerror=None: (_ for _ in ()).throw(PermissionError("held")))
    waits = []
    assert uninstall.remove_data(data, attempts=3, wait=1, sleep=waits.append) is False
    assert len(waits) == 2 and data.exists()


# ---- all together ----------------------------------------------------------------------------------------------
def test_cleanup_removes_rules_startup_entry_and_data(tmp_path):
    data = make_data(tmp_path)
    reg = FakeRegistry()
    autostart.set_enabled(True, r"C:\Program Files\Horizon Events\HorizonEvents.exe", reg, frozen=True)
    fw = FakeFirewall(["8.8.4.4"])
    code = uninstall.cleanup(data, fw.runner, fw.elevator, registry=reg, sleep=lambda s: None)
    assert code == uninstall.OK
    assert fw.ips == [] and autostart.is_enabled(registry=reg) is False and not data.exists()


def test_cleanup_reports_what_could_not_be_removed(tmp_path, monkeypatch):
    data = make_data(tmp_path)
    fw = FakeFirewall(["8.8.4.4"], grant=False)
    assert uninstall.cleanup(data, fw.runner, fw.elevator, registry=FakeRegistry(), sleep=lambda s: None) == uninstall.FIREWALL_REMAINS
    monkeypatch.setattr(uninstall.shutil, "rmtree", lambda path, onerror=None: (_ for _ in ()).throw(PermissionError("held")))
    data2 = make_data(tmp_path / "again")
    assert uninstall.cleanup(data2, fw.runner, fw.elevator, registry=FakeRegistry(), sleep=lambda s: None) == \
        uninstall.FIREWALL_REMAINS + uninstall.DATA_REMAINS


def test_cleanup_still_removes_the_data_if_the_firewall_step_crashes(tmp_path):
    data = make_data(tmp_path)

    def broken(args, timeout):
        raise RuntimeError("boom")

    assert uninstall.cleanup(data, broken, lambda *a: (0, ""), registry=FakeRegistry(), sleep=lambda s: None) == uninstall.FIREWALL_REMAINS
    assert not data.exists()


# ---- the running marker ----------------------------------------------------------------------------------------
@pytest.mark.skipif(sys.platform != "win32", reason="named mutexes are a Windows feature")
def test_the_running_marker_can_be_seen_by_other_programs():
    import ctypes

    assert uninstall.hold_running_mutex() is True
    handle = ctypes.windll.kernel32.OpenMutexW(0x00100000, False, uninstall.RUNNING_MUTEX)  # SYNCHRONIZE
    assert handle
    ctypes.windll.kernel32.CloseHandle(handle)


def test_the_marker_name_matches_the_one_the_installer_checks():
    from pathlib import Path

    iss = (Path(__file__).resolve().parents[2] / "installer" / "HorizonEvents.iss").read_text(encoding="utf-8")
    assert f"CheckForMutexes('{uninstall.RUNNING_MUTEX}')" in iss
    assert "--uninstall-cleanup" in iss
