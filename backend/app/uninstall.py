"""What the uninstaller needs from the app: a marker that says the app is running, and a clean-up that removes
everything the app put on the computer outside its install folder (its data, its firewall rules, its start-up entry).

The uninstaller runs `HorizonEvents.exe --uninstall-cleanup` once it has checked that no copy is running.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import shutil
import stat
import sys
import tempfile
import time
from pathlib import Path

from app.mitigation import firewall
from app.mitigation.elevate import run_elevated
from app.shell import autostart
from app.system.winutil import run_command

log = logging.getLogger(__name__)

RUNNING_MUTEX = "HorizonEvents.Running"  # the installer's uninstaller looks for this name
DATA_FOLDER_NAME = "HorizonEvents"

OK, FIREWALL_REMAINS, DATA_REMAINS = 0, 2, 4  # exit codes are added together when more than one thing went wrong

_RULE = re.compile(re.escape(firewall.RULE_PREFIX) + r"([0-9A-Fa-f:.]+)")
_handles: list = []


def hold_running_mutex() -> bool:
    """Create the named marker that exists for as long as this process runs. Returns False off Windows."""
    if sys.platform != "win32":
        return False
    import ctypes

    handle = ctypes.windll.kernel32.CreateMutexW(None, False, RUNNING_MUTEX)
    if handle:
        _handles.append(handle)  # never closed on purpose: it must live until the process ends
    return bool(handle)


def default_data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local" / "share")
    return Path(base) / DATA_FOLDER_NAME


# ---- firewall rules --------------------------------------------------------------------------------------------
def find_block_rules(runner=run_command) -> list[str]:
    """Addresses of the firewall rules this app added. Matches the rule name only, so it works in any Windows language."""
    try:
        _, out = runner([firewall.netsh(), "advfirewall", "firewall", "show", "rule", "name=all"], timeout=90.0)
    except (OSError, TimeoutError):
        return []
    found: list[str] = []
    for match in _RULE.finditer(out):
        try:
            ip = str(ipaddress.ip_address(match.group(1).rstrip(".:")))
        except ValueError:
            continue
        if ip not in found:
            found.append(ip)
    return found


def remove_block_rules(runner=run_command, elevator=run_elevated, temp_dir: Path | None = None) -> bool:
    """Remove every rule the app added, with a single Windows permission prompt. True when none is left."""
    addresses = find_block_rules(runner)
    if not addresses:
        return True
    # one netsh script, so the user sees a single Windows prompt however many rules there are; the names come
    # from `ipaddress`, so nothing but addresses can reach the script
    lines = [f'advfirewall firewall delete rule name="{firewall.rule_name(ip)}"' for ip in addresses]
    with tempfile.NamedTemporaryFile("w", suffix=".txt", prefix="hz-netsh-", dir=temp_dir, delete=False,
                                     encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    script = Path(fh.name)
    try:
        elevator(firewall.netsh(), ["-f", str(script)])
    finally:
        script.unlink(missing_ok=True)
    return not find_block_rules(runner)


# ---- start-up entry and data -----------------------------------------------------------------------------------
def remove_autostart(registry=None) -> None:
    try:
        autostart.set_enabled(False, None, registry)
    except (autostart.AutostartError, OSError):
        log.exception("could not remove the start-up entry")


def _writable(func, path, _exc_info) -> None:
    os.chmod(path, stat.S_IWRITE)  # read-only files must not stop the clean-up
    func(path)


def remove_data(data_dir: Path, attempts: int = 5, wait: float = 1.0, sleep=time.sleep) -> bool:
    """Delete the whole data folder (database, quarantine, backups it made, settings, logs). True when it is gone.
    Only a folder named like the app's own is touched. Files can be held for a moment by the window component that
    has just closed, so it tries a few times."""
    data_dir = Path(data_dir)
    if data_dir.name != DATA_FOLDER_NAME:
        raise ValueError(f"refusing to delete a folder that is not the app's data folder: {data_dir}")
    for attempt in range(attempts):
        if not data_dir.exists():
            return True
        try:
            shutil.rmtree(data_dir, onerror=_writable)
        except OSError:
            pass
        if not data_dir.exists():
            return True
        if attempt < attempts - 1:
            sleep(wait)
    return not data_dir.exists()


def cleanup(data_dir: Path | None = None, runner=run_command, elevator=run_elevated, registry=None,
            sleep=time.sleep) -> int:
    """Remove everything outside the install folder. Returns OK (0), or the sum of FIREWALL_REMAINS and DATA_REMAINS."""
    code = OK
    if sys.platform == "win32" or registry is not None:
        try:
            if not remove_block_rules(runner, elevator):
                code += FIREWALL_REMAINS
        except Exception:
            log.exception("removing firewall rules failed")
            code += FIREWALL_REMAINS
        remove_autostart(registry)
    if not remove_data(data_dir or default_data_dir(), sleep=sleep):
        code += DATA_REMAINS
    return code
