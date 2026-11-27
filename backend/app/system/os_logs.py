"""Collectors for the logs that are not plain files: systemd's journal on Linux and the unified log on macOS.

Both are read by running the operating system's own tool (`journalctl`, `log show`) with a fixed argument list and no
shell. Entries become the classic syslog line and go through the same parsers as every other Linux log, so a failed SSH
login looks the same wherever it was read from. The tool is injectable so the logic is tested without the real log."""
from __future__ import annotations

import json
import shutil
import socket
import time
from datetime import datetime, timedelta, timezone
from typing import Callable

from sqlalchemy.orm import Session

from app.database.collector_models import CollectorSettingRow, get_setting, set_setting
from app.services.ingestion import import_logs
from app.syslog import lines as syslog_lines
from app.system.base import NEEDS_PERMISSION, READY, UNAVAILABLE, Collector
from app.system.winutil import run_command

MAX_ENTRIES = 5000  # per poll; the rest is read on the next one
Runner = Callable[[list[str]], "tuple[int, str]"]

# The macOS processes that report sign-ins, privilege changes and remote access.
MAC_PROGRAMS = ("sshd", "sudo", "su", "login", "loginwindow", "authd", "screensharingd", "securityd", "opendirectoryd")


def _micro(dt: datetime) -> int:
    return int(dt.replace(tzinfo=timezone.utc).timestamp() * 1_000_000)


def _since(micro: int) -> datetime:
    return datetime.fromtimestamp(micro / 1_000_000, tz=timezone.utc).replace(tzinfo=None)


def _import(session: Session, lines: list[str], name: str) -> int:
    imported = 0
    for source_type, content in syslog_lines.route(lines).items():
        imported += import_logs(session, source_type, name, content)["imported"]
    return imported


class _OsLogCollector(Collector):
    """Shared bookkeeping: the bookmark is the newest entry time seen, in microseconds since 1970.

    It is kept as text in the app settings, not in the collector settings' integer column: a microsecond time is far
    larger than the 32-bit integer that PostgreSQL gives that column."""

    def __init__(self, runner: Runner = run_command):
        self._runner = runner

    def bookmark(self, session: Session) -> int:
        try:
            return int(get_setting(session, f"bookmark:{self.id}", "0") or 0)
        except ValueError:
            return 0

    def save_bookmark(self, session: Session, value: int) -> None:
        set_setting(session, f"bookmark:{self.id}", str(int(value)))

    def _start(self, session: Session, setting: CollectorSettingRow) -> int | None:
        """The time to read from (microseconds), or None when this is the first run and we only follow from now."""
        saved = self.bookmark(session)
        if saved:
            return saved
        if setting.backfill_hours:
            start = int(time.time() * 1_000_000) - setting.backfill_hours * 3_600_000_000
            setting.backfill_hours = None
            return start
        self.save_bookmark(session, int(time.time() * 1_000_000))  # first run: follow from now, no history flood
        return None

    def _run(self, args: list[str]) -> str:
        try:
            rc, out = self._runner(args)
        except (OSError, TimeoutError) as exc:
            raise RuntimeError(f"{args[0]} could not run: {exc}") from exc
        if rc != 0:
            raise RuntimeError(f"{args[0]} exited with code {rc}")
        return out


class JournaldCollector(_OsLogCollector):
    id = "linux-journal"
    name = "Linux system journal (journald)"
    description = "Sign-in activity and service failures from systemd's journal, for systems that keep no log files."
    platform = "linux"

    def __init__(self, runner: Runner = run_command, tool: Callable[[str], str | None] = shutil.which):
        super().__init__(runner)
        self._tool = tool

    def access(self) -> str:
        if self._tool("journalctl") is None:
            return UNAVAILABLE
        try:
            rc, _ = self._runner(["journalctl", "-n", "0", "-q", "--no-pager"])
        except (OSError, TimeoutError):
            return UNAVAILABLE
        return READY if rc == 0 else NEEDS_PERMISSION  # without the right group the journal opens no files

    def poll(self, session: Session, setting: CollectorSettingRow) -> int:
        start = self._start(session, setting)
        if start is None:
            return 0
        out = self._run(["journalctl", "-o", "json", "--no-pager", "--utc", "-q", "-n", str(MAX_ENTRIES),
                         "--since", _since(start).strftime("%Y-%m-%d %H:%M:%S")])
        entries, newest = [], start
        for raw in out.splitlines():
            try:
                e = json.loads(raw)
                at = int(e["__REALTIME_TIMESTAMP"])
            except (ValueError, KeyError, TypeError):
                continue
            if at <= start:
                continue  # already read (the time filter only has whole seconds)
            newest = max(newest, at)
            message = e.get("MESSAGE")
            if not isinstance(message, str):  # binary or missing messages carry nothing we can read
                continue
            entries.append((at, syslog_lines.format_line(
                _since(at), e.get("_HOSTNAME") or socket.gethostname(),
                e.get("SYSLOG_IDENTIFIER") or e.get("_COMM") or "unknown", e.get("_PID"), message)))
        imported = _import(session, [line for _, line in sorted(entries)], "journald") if entries else 0
        self.save_bookmark(session, newest)  # advanced only after the lines were stored
        return imported


class MacLogCollector(_OsLogCollector):
    id = "mac-log"
    name = "macOS system log"
    description = "SSH, sudo, login window and screen-sharing activity from the macOS unified log."
    platform = "mac"

    def __init__(self, runner: Runner = run_command, tool: Callable[[str], str | None] = shutil.which):
        super().__init__(runner)
        self._tool = tool

    @staticmethod
    def predicate() -> str:
        return " OR ".join(f'process == "{p}"' for p in MAC_PROGRAMS)

    def access(self) -> str:
        if self._tool("log") is None:
            return UNAVAILABLE
        try:
            rc, _ = self._runner(["log", "show", "--last", "1s", "--style", "ndjson", "--predicate", "process == \"sshd\""])
        except (OSError, TimeoutError):
            return UNAVAILABLE
        return READY if rc == 0 else NEEDS_PERMISSION

    def poll(self, session: Session, setting: CollectorSettingRow) -> int:
        start = self._start(session, setting)
        if start is None:
            return 0
        local = datetime.fromtimestamp(start / 1_000_000)  # `log show` reads the start time as local time
        out = self._run(["log", "show", "--style", "ndjson", "--info", "--predicate", self.predicate(),
                         "--start", local.strftime("%Y-%m-%d %H:%M:%S")])
        host, entries, newest = socket.gethostname(), [], start
        for raw in out.splitlines():
            try:
                e = json.loads(raw)
                when = datetime.fromisoformat(str(e["timestamp"]).replace(" ", "T", 1))
            except (ValueError, KeyError, TypeError):
                continue
            at = _micro(when.astimezone(timezone.utc).replace(tzinfo=None) if when.tzinfo else when)
            if at <= start:
                continue
            newest = max(newest, at)
            message = e.get("eventMessage")
            if not isinstance(message, str):
                continue
            program = str(e.get("processImagePath") or "").rsplit("/", 1)[-1] or "unknown"
            entries.append((at, syslog_lines.format_line(_since(at), host, program, e.get("processID"), message)))
        entries = sorted(entries)
        if len(entries) > MAX_ENTRIES:  # take the oldest first; the bookmark stops there and the rest comes next time
            entries = entries[:MAX_ENTRIES]
            newest = entries[-1][0]
        imported = _import(session, [line for _, line in entries], "macos-log") if entries else 0
        self.save_bookmark(session, newest)
        return imported
