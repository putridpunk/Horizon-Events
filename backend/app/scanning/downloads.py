"""Scan files as they arrive in the Downloads folder (opt-in).

Files that were already there when watching began are not scanned. A new file is scanned once its size and
modification time have stopped changing between two checks, so half-downloaded files are left alone.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Callable

from sqlalchemy.orm import Session

from app.database.collector_models import get_setting, set_setting
from app.scanning.service import ScanBusy

log = logging.getLogger(__name__)

SETTING_KEY = "scan_downloads"
TEMP_SUFFIXES = (".crdownload", ".part", ".tmp", ".download", ".partial", ".opdownload")
MAX_BATCH = 20


class DownloadsError(ValueError):
    """A request that cannot be accepted; the message is shown to the user."""


def default_folder() -> str:
    return str(Path.home() / "Downloads")


def load_config(session: Session) -> dict:
    try:
        stored = json.loads(get_setting(session, SETTING_KEY, "{}") or "{}")
    except ValueError:
        stored = {}
    folder = stored.get("folder") or ""
    return {"enabled": bool(stored.get("enabled", False)), "folder": folder, "default_folder": default_folder(),
            "effective_folder": folder or default_folder()}


def save_config(session: Session, enabled: bool | None = None, folder: str | None = None) -> dict:
    current = load_config(session)
    if enabled is not None:
        current["enabled"] = bool(enabled)
    if folder is not None:
        folder = folder.strip()
        if folder:
            if "\x00" in folder or folder.startswith(("\\\\", "//")) or not os.path.isabs(folder):
                raise DownloadsError("Choose a folder on this computer.")
            if not os.path.isdir(folder):
                raise DownloadsError("That folder does not exist.")
        current["folder"] = folder
    set_setting(session, SETTING_KEY, json.dumps({"enabled": current["enabled"], "folder": current["folder"]}))
    return load_config(session)


class DownloadsWatcher:
    def __init__(self, session_factory: Callable[[], Session], scans, interval: float = 5.0):
        self.session_factory, self.scans, self.interval = session_factory, scans, interval
        self._folder: str | None = None
        self._known: dict[str, tuple[int, int]] | None = None  # files already handled: path -> (size, mtime)
        self._candidates: dict[str, tuple[int, int]] = {}
        self._ready: list[str] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.scanned = 0

    # -- state ---------------------------------------------------------------------------------------------------
    def status(self) -> dict:
        return {"watching": self._known is not None, "queued": len(set(self._ready) | set(self._candidates)),
                "scanned": self.scanned}

    def _reset(self) -> None:
        self._known, self._folder = None, None
        self._candidates, self._ready = {}, []

    @staticmethod
    def _listing(folder: str) -> dict[str, tuple[int, int]]:
        out = {}
        with os.scandir(folder) as it:
            for entry in it:
                try:
                    if not entry.is_file(follow_symlinks=False) or entry.name.lower().endswith(TEMP_SUFFIXES):
                        continue
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                out[entry.path] = (st.st_size, st.st_mtime_ns)
        return out

    def tick(self) -> None:
        with self.session_factory() as session:
            cfg = load_config(session)
        if not cfg["enabled"] or self.scans is None:
            return self._reset()
        folder = cfg["effective_folder"]
        if not os.path.isdir(folder):
            return self._reset()
        current = self._listing(folder)
        if self._known is None or self._folder != folder:  # first look: what is already here is not scanned
            self._known, self._folder = dict(current), folder
            return
        self._candidates = {p: s for p, s in self._candidates.items() if current.get(p) == s or p in current}
        for path, sig in current.items():
            if self._known.get(path) == sig:
                continue
            if self._candidates.get(path) == sig:  # unchanged since the last check: the download is finished
                if path not in self._ready:
                    self._ready.append(path)
            else:
                self._candidates[path] = sig
                if path in self._ready:
                    self._ready.remove(path)
        self._ready = [p for p in self._ready if p in current]
        if self._ready:
            self._scan(current)

    def _scan(self, current: dict[str, tuple[int, int]]) -> None:
        batch = self._ready[:MAX_BATCH]
        try:
            self.scans.start(batch)
        except ScanBusy:
            return  # try again at the next check
        except ValueError:
            self._ready = [p for p in self._ready if os.path.exists(p)]
            return
        for path in batch:
            self._known[path] = current.get(path, (0, 0))
            self._candidates.pop(path, None)
        self._ready = self._ready[len(batch):]
        self.scanned += len(batch)

    # -- thread --------------------------------------------------------------------------------------------------
    def start(self) -> None:
        def loop():
            while not self._stop.wait(self.interval):
                try:
                    self.tick()
                except Exception:
                    log.exception("watching the downloads folder failed")
        self._thread = threading.Thread(target=loop, name="downloads-watch", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
