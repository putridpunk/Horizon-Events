"""Reads this machine's Windows Event Log through the built-in `wevtutil` tool.

Only a short, fixed list of security-relevant event IDs is ever requested. `wevtutil` is run through an
injectable runner so the logic can be tested without a real log, and its *exit codes* (not its localised
messages) decide the access state.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Callable

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException
from sqlalchemy.orm import Session

from app.database.collector_models import CollectorSettingRow
from app.services.ingestion import import_logs
from app.system.base import NEEDS_PERMISSION, READY, UNAVAILABLE, Collector
from app.system.winutil import run_command, system_tool

BATCH_SIZE = 200
EXIT_ACCESS_DENIED = 5

Runner = Callable[[list[str]], "tuple[int, str]"]


class CollectorError(RuntimeError):
    pass


@dataclass(frozen=True)
class ChannelSpec:
    channel: str
    name: str
    description: str
    event_ids: tuple[int, ...]
    logon_types: tuple[int, ...] = ()  # when set, 4624 (successful logon) is read for these logon types only
    ntlm_network: bool = False  # also read 4624 network logons (type 3) that used NTLM


CHANNELS: dict[str, ChannelSpec] = {
    "Security": ChannelSpec(
        "Security", "Windows Security log",
        "Sign-in activity: failed and successful logons, account lockouts, new accounts, changes to "
        "privileged groups, new services and scheduled tasks, and a cleared audit log. Reading it needs a "
        "one-time permission.",
        event_ids=(4625, 4740, 4720, 4728, 4732, 4756, 1102, 4697, 4698, 4648, 6416),
        logon_types=(2, 7, 10, 11), ntlm_network=True),
    "System": ChannelSpec(
        "System", "Windows System log", "Services that crash, stop unexpectedly or are newly installed, and a cleared log.",
        event_ids=(7031, 7034, 7045, 104)),
    "Application": ChannelSpec(
        "Application", "Windows Application log", "Applications that crash.", event_ids=(1000,)),
    "PowerShell": ChannelSpec(
        "Microsoft-Windows-PowerShell/Operational", "Windows PowerShell log",
        "PowerShell scripts that ran (script block logging, event 4104). Windows only writes these if script block "
        "logging is turned on.", event_ids=(4104,)),
}


def run_wevtutil(args: list[str], timeout: float = 20.0) -> tuple[int, str]:
    """Run `wevtutil` (by full path) and return (exit code, stdout). Raises TimeoutError, or OSError if it
    cannot start."""
    return run_command([system_tool("wevtutil.exe"), *args], timeout)


def build_query(spec: ChannelSpec, after_id: int | None, backfill_ms: int | None = None) -> str:
    """XPath for the channel's events: only the listed IDs, newer than `after_id`, or within a time window."""
    extra = []
    if after_id is not None:
        extra.append(f"(EventRecordID>{after_id})")
    if backfill_ms is not None:
        extra.append(f"TimeCreated[timediff(@SystemTime) <= {backfill_ms}]")

    def system(ids: tuple[int, ...]) -> str:
        ids_expr = " or ".join(f"EventID={i}" for i in ids)
        return "System[" + " and ".join([f"({ids_expr})", *extra]) + "]"

    clauses = [f"*[{system(spec.event_ids)}]"]
    if spec.logon_types:
        types = " or ".join(f"(Data[@Name='LogonType']='{t}')" for t in spec.logon_types)
        if spec.ntlm_network:
            types += " or ((Data[@Name='LogonType']='3') and (Data[@Name='AuthenticationPackageName']='NTLM'))"
        clauses.append(f"*[{system((4624,))} and EventData[{types}]]")
    return " or ".join(clauses)


def wrap(xml: str) -> str:
    """`wevtutil` prints concatenated <Event> elements with no root; give them one."""
    return "<Events>" + xml + "</Events>"


def record_ids(xml: str) -> list[int]:
    """EventRecordID of every event in wevtutil output. Raises CollectorError on malformed output."""
    if not xml.strip():
        return []
    try:
        root = ET.fromstring(wrap(xml))
    except (ET.ParseError, DefusedXmlException) as exc:
        raise CollectorError(f"could not parse wevtutil output: {exc}") from exc
    return [int(el.text) for el in root.iter() if el.tag.rsplit("}", 1)[-1] == "EventRecordID" and (el.text or "").isdigit()]


class WindowsEventLogCollector(Collector):
    platform = "windows"

    def __init__(self, channel: str, runner: Runner = run_wevtutil, refine: Callable[[str], str] | None = None):
        self.spec = CHANNELS[channel]
        self.id = f"windows-{channel.lower()}"
        self.name, self.description = self.spec.name, self.spec.description
        self._runner, self._refine = runner, refine

    # -- access ---------------------------------------------------------------------------
    def access(self) -> str:
        if self._runner is run_wevtutil and sys.platform != "win32":
            return UNAVAILABLE
        try:  # a query that matches nothing: checks access without reading any event
            rc, _ = self._runner(["qe", self.spec.channel, "/q:*[System[(EventID=0)]]", "/c:1", "/f:xml"])
            state = READY if rc == 0 else NEEDS_PERMISSION if rc == EXIT_ACCESS_DENIED else UNAVAILABLE
        except (OSError, TimeoutError):
            state = UNAVAILABLE
        return self._refine(state) if self._refine else state

    # -- reading --------------------------------------------------------------------------
    def _run(self, args: list[str]) -> str:
        try:
            rc, out = self._runner(args)
        except TimeoutError as exc:
            raise CollectorError("wevtutil timed out") from exc
        except OSError as exc:
            raise CollectorError(f"wevtutil could not run: {exc}") from exc
        if rc != 0:
            raise CollectorError(f"wevtutil exited with code {rc}")
        return out

    def _newest_record_id(self) -> int:
        return max(record_ids(self._run(["qe", self.spec.channel, "/rd:true", "/c:1", "/f:xml"])), default=0)

    def poll(self, session: Session, setting: CollectorSettingRow) -> int:
        bookmark = setting.last_record_id or 0
        if bookmark == 0 and not setting.backfill_hours:
            setting.last_record_id = self._newest_record_id()  # first run: follow from now, no history flood
            return 0
        backfill_ms = setting.backfill_hours * 3_600_000 if (bookmark == 0 and setting.backfill_hours) else None
        total = 0
        while True:
            query = build_query(self.spec, bookmark or None, None if bookmark else backfill_ms)
            xml = self._run(["qe", self.spec.channel, f"/q:{query}", "/f:xml", f"/c:{BATCH_SIZE}"])
            ids = record_ids(xml)
            if not ids:
                break
            result = import_logs(session, "windows", f"EventLog:{self.spec.channel}", wrap(xml).encode("utf-8"))
            total += result["imported"]
            bookmark = max(ids)  # advanced only now that the batch is safely stored
            setting.last_record_id = bookmark
            session.commit()
            if len(ids) < BATCH_SIZE:
                break
        if setting.backfill_hours:
            setting.backfill_hours = None  # the one-shot backfill is done
            if not setting.last_record_id:
                setting.last_record_id = self._newest_record_id()  # nothing matched: follow from now
        return total
