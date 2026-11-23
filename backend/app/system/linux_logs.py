"""Linux log files as collectors: the first of a fixed list of well-known paths that exists is followed."""
from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy.orm import Session

from app.database.collector_models import CollectorSettingRow
from app.services.ingestion import import_logs
from app.system.base import NEEDS_PERMISSION, READY, UNAVAILABLE, Collector
from app.watcher.tailer import FileTailer


class LinuxLogCollector(Collector):
    platform = "linux"

    def __init__(self, id: str, name: str, source_type: str, paths: list[Path], description: str):
        self.id, self.name, self.source_type, self.description = id, name, source_type, description
        self.paths = [Path(p) for p in paths]

    def active_path(self) -> Path | None:
        return next((p for p in self.paths if p.is_file()), None)

    def access(self) -> str:
        path = self.active_path()
        if path is None:
            return UNAVAILABLE
        return READY if os.access(path, os.R_OK) else NEEDS_PERMISSION

    def poll(self, session: Session, setting: CollectorSettingRow) -> int:
        path = self.active_path()
        if path is None:
            return 0
        tailer = FileTailer()
        # The bookmark stores offset + 1 so that 0 can mean "never polled" even when the file is empty.
        if not setting.last_record_id:
            tailer.offset = 0 if setting.backfill_hours else path.stat().st_size  # first run: follow from now
            setting.backfill_hours = None
            setting.last_record_id = tailer.offset + 1
            if tailer.offset:
                return 0
        else:
            tailer.offset = setting.last_record_id - 1
        data = tailer.read_new(path)
        imported = 0
        if data:
            imported = import_logs(session, self.source_type, path.name, data)["imported"]
        setting.last_record_id = tailer.offset + 1  # advanced only after the lines were stored
        return imported


def default_linux_collectors() -> list[LinuxLogCollector]:
    return [
        LinuxLogCollector("linux-auth", "Linux authentication log", "linux_auth",
                          [Path("/var/log/auth.log"), Path("/var/log/secure")],
                          "Sign-in activity: SSH logins and failures, sudo and account events."),
        LinuxLogCollector("linux-syslog", "Linux system log", "linux_syslog",
                          [Path("/var/log/syslog"), Path("/var/log/messages")],
                          "System messages, including services that fail or restart."),
    ]
