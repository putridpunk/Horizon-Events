"""One-time access to the Windows Security log.

Reading the Security log needs membership of the built-in *Event Log Readers* group (or administrator
rights). This module can *ask Windows* to add the current user to that group; Windows shows its own
permission prompt, and nothing happens unless the user approves it. The group is identified by its
well-known SID so this works on every Windows language, and the user by SID, so no account name is ever
placed in a command line.

Windows applies a new group membership to a session only after the user signs out and in again, so there
is a "waiting for sign-out" state between granting and being able to read.
"""
from __future__ import annotations

import csv
import io
import re
import subprocess
import sys
from typing import Callable

from app.system.base import NEEDS_PERMISSION, READY, UNAVAILABLE, WAITING_SIGNOUT
from app.system.winutil import run_command, system_tool

SECURITY_READERS_SID = "S-1-5-32-573"  # BUILTIN\Event Log Readers
_SID = re.compile(r"^S-1-\d+(?:-\d+){3,14}$")  # real user SIDs have at least four numeric parts after S-1-

Runner = Callable[..., "tuple[int, str]"]


def powershell_path() -> str:
    return system_tool("WindowsPowerShell", "v1.0", "powershell.exe")


def _is_sid(value: object) -> bool:
    return isinstance(value, str) and _SID.fullmatch(value) is not None


def enable_command(user_sid: str) -> list[str]:
    """The command that adds the user to Event Log Readers. Built only from a validated SID."""
    if not _is_sid(user_sid):
        raise ValueError("a valid user SID is required")
    return [powershell_path(), "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
            f"Add-LocalGroupMember -SID {SECURITY_READERS_SID} -Member {user_sid}"]


def request_elevation(command: list[str], shell: Callable | None = None) -> bool:
    """Ask Windows to run `command` as administrator (it shows its own permission prompt).

    Returns True if Windows accepted the request, False if it was declined or is unavailable. This code
    only *requests* the prompt; it never runs the command itself.
    """
    if sys.platform != "win32":
        return False
    if shell is None:
        import ctypes
        shell = ctypes.windll.shell32.ShellExecuteW
    result = shell(None, "runas", command[0], subprocess.list2cmdline(command[1:]), None, 0)
    return int(result) > 32  # ShellExecute returns a value above 32 on success


def current_user_sid(runner: Runner = run_command) -> str | None:
    """SID of the account this app runs as, from `whoami /user`. None if it cannot be determined."""
    try:
        rc, out = runner([system_tool("whoami.exe"), "/user", "/fo", "csv", "/nh"])
    except (OSError, TimeoutError):
        return None
    if rc != 0:
        return None
    for row in csv.reader(io.StringIO(out)):
        if len(row) >= 2 and _is_sid(row[1].strip()):
            return row[1].strip()
    return None


def is_member(user_sid: str, runner: Runner = run_command) -> bool:
    """Whether the user is already in Event Log Readers (compared by SID, so the language does not matter)."""
    if not _is_sid(user_sid):
        return False
    script = (f"(Get-LocalGroupMember -SID {SECURITY_READERS_SID} | ForEach-Object {{ $_.SID.Value }}) -join [Environment]::NewLine")
    try:
        rc, out = runner([powershell_path(), "-NoProfile", "-NonInteractive", "-Command", script])
    except (OSError, TimeoutError):
        return False
    return rc == 0 and user_sid in {line.strip() for line in out.splitlines()}


def token_has_group(runner: Runner = run_command) -> bool:
    """Whether the *current session* already carries the group (true only after signing out and in)."""
    try:
        rc, out = runner([system_tool("whoami.exe"), "/groups", "/fo", "csv", "/nh"])
    except (OSError, TimeoutError):
        return False
    if rc != 0:
        return False
    return any(len(row) >= 3 and row[2].strip() == SECURITY_READERS_SID for row in csv.reader(io.StringIO(out)))


def security_state(probe: str, member: bool, in_token: bool) -> str:
    """Combine what the log probe said with the group facts into the state shown to the user."""
    if probe == READY:
        return READY
    if probe == NEEDS_PERMISSION:
        return WAITING_SIGNOUT if (member and not in_token) else NEEDS_PERMISSION
    return UNAVAILABLE


def make_security_refine(runner: Runner = run_command) -> Callable[[str], str]:
    """A hook for the Security collector: it turns a plain probe result into the richer state. The helper
    tools are only run when access was actually denied."""
    def refine(probe: str) -> str:
        if probe != NEEDS_PERMISSION:
            return probe
        sid = current_user_sid(runner)
        member = bool(sid) and is_member(sid, runner)
        return security_state(probe, member, token_has_group(runner) if member else False)
    return refine
