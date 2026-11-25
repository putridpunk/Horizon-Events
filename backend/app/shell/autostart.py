"""Start Horizon Events when the user signs in to Windows, through the per-user Run registry key.

This needs no administrator rights and affects only the current user. The program is started with --background,
so it opens in the system tray instead of in front of whatever the user is doing.
"""
from __future__ import annotations

import os
import sys

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "HorizonEvents"


class AutostartError(ValueError):
    """A request that cannot be carried out; the message is shown to the user."""


def command_for(exe: str) -> str:
    return f'"{exe}" --background'


def _winreg(module=None):
    if module is not None:
        return module
    if sys.platform != "win32":
        raise AutostartError("Starting with Windows is only available on Windows.")
    import winreg
    return winreg


def is_enabled(exe: str | None = None, registry=None) -> bool:
    """Whether the Run entry exists and points at this program."""
    try:
        reg = _winreg(registry)
        with reg.OpenKey(reg.HKEY_CURRENT_USER, RUN_KEY, 0, reg.KEY_READ) as key:
            value, _ = reg.QueryValueEx(key, VALUE_NAME)
    except (OSError, AutostartError):
        return False
    return exe is None or value == command_for(exe)


def set_enabled(enabled: bool, exe: str | None, registry=None, frozen: bool | None = None) -> None:
    reg = _winreg(registry)
    if enabled:
        if frozen is None:
            frozen = bool(getattr(sys, "frozen", False))
        if not frozen or not exe or not os.path.isabs(exe):
            raise AutostartError("Starting with Windows works from the installed app, not when running from source.")
        with reg.CreateKey(reg.HKEY_CURRENT_USER, RUN_KEY) as key:
            reg.SetValueEx(key, VALUE_NAME, 0, reg.REG_SZ, command_for(exe))
    else:
        try:
            with reg.OpenKey(reg.HKEY_CURRENT_USER, RUN_KEY, 0, reg.KEY_SET_VALUE) as key:
                reg.DeleteValue(key, VALUE_NAME)
        except FileNotFoundError:
            pass  # it was not set
