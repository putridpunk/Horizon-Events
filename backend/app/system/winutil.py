"""Small helpers for calling Windows system tools safely: by full path, without a console window."""
from __future__ import annotations

import os
import subprocess
import sys


def system_tool(*parts: str) -> str:
    """Full path under %SystemRoot%\\System32, so the tool does not depend on PATH (which a shell or a
    non-Windows `whoami` could shadow). Off Windows this is just the bare name."""
    if sys.platform != "win32":
        return parts[-1]
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", *parts)


def run_command(args: list[str], timeout: float = 20.0) -> tuple[int, str]:
    """Run a command (no shell) and return (exit code, stdout). Raises TimeoutError, or OSError if it
    cannot start."""
    flags = 0x08000000 if sys.platform == "win32" else 0  # CREATE_NO_WINDOW: no console flash in the app
    try:
        done = subprocess.run(args, capture_output=True, timeout=timeout, creationflags=flags)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"{os.path.basename(args[0])} timed out") from exc
    return done.returncode, done.stdout.decode("utf-8", errors="replace")
