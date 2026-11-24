"""Run one program as administrator through Windows' own permission prompt, and wait for it.

Nothing is cached: every call shows the prompt. The app never holds administrator rights between calls.
"""
from __future__ import annotations

import subprocess
import sys

ERROR_CANCELLED = 1223  # the user pressed No in the prompt
WAIT_MS = 120_000


def run_elevated(exe: str, args: list[str]) -> tuple[int | None, str]:
    """(exit code, message). The exit code is None when the program did not run (declined or unavailable)."""
    if sys.platform != "win32":
        return None, "Blocking addresses is only available on Windows."
    import ctypes
    from ctypes import wintypes

    class ShellExecuteInfo(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wintypes.HWND),
                    ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                    ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                    ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
                    ("dwHotKey", wintypes.DWORD), ("hIconOrMonitor", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]

    info = ShellExecuteInfo()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x00000040  # SEE_MASK_NOCLOSEPROCESS: keep the handle so we can wait for the result
    info.lpVerb = "runas"
    info.lpFile = exe
    info.lpParameters = subprocess.list2cmdline(args)
    info.nShow = 0  # hidden
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)):
        code = ctypes.GetLastError()
        if code == ERROR_CANCELLED:
            return None, "Windows permission was not granted."
        return None, f"Windows could not start the program (error {code})."
    kernel32 = ctypes.windll.kernel32
    try:
        kernel32.WaitForSingleObject(info.hProcess, WAIT_MS)
        exit_code = wintypes.DWORD()
        kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(exit_code))
        return int(exit_code.value), ""
    finally:
        kernel32.CloseHandle(info.hProcess)
