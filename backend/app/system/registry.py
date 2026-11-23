"""Which collectors exist on this machine."""
from __future__ import annotations

import sys

from app.system.access import make_security_refine
from app.system.base import Collector
from app.system.linux_logs import default_linux_collectors
from app.system.windows_eventlog import WindowsEventLogCollector


def platform_name() -> str:
    return {"win32": "windows", "linux": "linux"}.get(sys.platform, "other")


def build_collectors() -> list[Collector]:
    if sys.platform == "win32":
        return [WindowsEventLogCollector("Security", refine=make_security_refine()),
                WindowsEventLogCollector("System"), WindowsEventLogCollector("Application")]
    if sys.platform.startswith("linux"):
        return list(default_linux_collectors())
    return []
