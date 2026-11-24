"""Microsoft Defender on-demand scanning through its command line (`MpCmdRun.exe`).

Report only: `-DisableRemediation` makes Defender list what it finds without deleting or quarantining anything.
The exit code is not a reliable verdict (a missing file and a detection both exit with 2), so the outcome is read
from Defender's own summary line ("found no threats" / "found N threats").
"""
from __future__ import annotations

import glob
import os
import re
import sys
from dataclasses import dataclass, field

from app.system.winutil import run_command

CLEAN, THREAT, ERROR = "clean", "threat", "error"
SCAN_TIMEOUT_SECONDS = 3600.0

_SUMMARY = re.compile(r"found\s+(no|\d+)\s+threats?", re.I)
_THREAT = re.compile(r"^\s*Threat\s*:\s*(.+?)\s*$", re.I)
_FILE = re.compile(r"^\s*file\s*:\s*(.+?)\s*$", re.I)


@dataclass
class Finding:
    threat: str
    path: str


@dataclass
class ScanOutcome:
    status: str  # clean | threat | error
    findings: list[Finding] = field(default_factory=list)
    message: str = ""


def find_defender() -> str | None:
    """Full path of MpCmdRun.exe (newest platform version first), or None when Defender is not installed."""
    if sys.platform != "win32":
        return None
    data = os.environ.get("ProgramData", r"C:\ProgramData")
    candidates = sorted(glob.glob(os.path.join(data, "Microsoft", "Windows Defender", "Platform", "*", "MpCmdRun.exe")),
                        reverse=True)
    candidates.append(os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Windows Defender",
                                   "MpCmdRun.exe"))
    return next((c for c in candidates if os.path.isfile(c)), None)


def parse_output(output: str, target: str) -> ScanOutcome:
    summary = _SUMMARY.search(output)
    if not summary:
        lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
        detail = next((ln for ln in lines if "fail" in ln.lower() or "error" in ln.lower()), lines[0] if lines else "")
        return ScanOutcome(ERROR, message=detail[:300] or "Microsoft Defender gave no result.")
    if summary.group(1).lower() == "no":
        return ScanOutcome(CLEAN)

    findings: list[Finding] = []
    threat = ""
    for line in output.splitlines():
        if (m := _THREAT.match(line)):
            threat = m.group(1)
        elif (m := _FILE.match(line)) and threat:
            path = m.group(1)
            if not os.path.exists(path) and os.path.isfile(target):  # garbled non-ASCII path in the output
                path = target
            findings.append(Finding(threat, path))
    if not findings:  # a detection we could not itemise is still a detection
        findings.append(Finding(threat or "Unidentified threat", target))
    return ScanOutcome(THREAT, findings)


def scan_path(path: str, runner=run_command, tool: str | None = None) -> ScanOutcome:
    tool = tool or find_defender()
    if not tool:
        return ScanOutcome(ERROR, message="Microsoft Defender was not found on this computer.")
    try:
        _, output = runner([tool, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"],
                           timeout=SCAN_TIMEOUT_SECONDS)
    except TimeoutError:
        return ScanOutcome(ERROR, message="The scan took too long and was stopped.")
    except OSError as exc:
        return ScanOutcome(ERROR, message=f"Microsoft Defender could not be started: {exc}")
    return parse_output(output, path)
