"""Background watcher: ingests new lines from files in a watch folder.

Layout: `<watch_dir>/<source_type>/<file>`; the subfolder name selects the parser. Only direct,
regular (non-symlink) files of known subfolders are read.
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Callable

from sqlalchemy.orm import Session

from app.collectors.base import SOURCE_TYPES
from app.domain import utcnow
from app.services.ingestion import import_logs
from app.watcher.tailer import FileTailer


class WatchService:
    def __init__(self, watch_dir: Path, session_factory: Callable[[], Session], interval: float = 2.0):
        self.dir = Path(watch_dir)
        self.session_factory = session_factory
        self.interval = interval
        self._tailers: dict[tuple[str, str], FileTailer] = {}
        self._stats: dict[tuple[str, str], dict] = {}
        self._lock = threading.Lock()
        self._paused = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -- scanning ---------------------------------------------------------------------------
    def scan_once(self) -> int:
        """Ingest new complete lines from every watched file. Returns events imported this pass."""
        if self._paused:
            return 0
        total = 0
        for source_type in SOURCE_TYPES:
            folder = self.dir / source_type
            try:
                folder.mkdir(parents=True, exist_ok=True)
                entries = sorted(folder.iterdir())
            except OSError:
                continue
            for path in entries:
                try:
                    if path.is_symlink() or not path.is_file():
                        continue
                except OSError:
                    continue
                total += self._scan_file(source_type, path)
        return total

    def _scan_file(self, source_type: str, path: Path) -> int:
        key = (source_type, path.name)
        with self._lock:
            tailer = self._tailers.setdefault(key, FileTailer())
            stats = self._stats.setdefault(key, {
                "path": f"{source_type}/{path.name}", "source_type": source_type, "lines": 0, "imported": 0,
                "skipped": 0, "alerts": 0, "last_activity": None, "last_error": None})
        previous = tailer.offset
        try:
            data = tailer.read_new(path)
            if not data:
                return 0
            session = self.session_factory()
            try:
                result = import_logs(session, source_type, path.name, data)
            finally:
                session.close()
        except Exception as exc:  # one bad file must never stop the watcher
            tailer.offset = previous  # retry the same lines on the next pass
            with self._lock:
                stats["last_error"] = f"{type(exc).__name__}: {exc}"
            return 0
        with self._lock:
            stats["lines"] += result["total"]
            stats["imported"] += result["imported"]
            stats["skipped"] += result["skipped"]
            stats["alerts"] += result["alerts_created"]
            stats["last_activity"] = utcnow().isoformat()
            stats["last_error"] = None
        return result["imported"]

    # -- lifecycle --------------------------------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="horizon-watcher", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.scan_once()
            except Exception:
                pass
            self._stop.wait(self.interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def pause(self) -> None:
        self._paused = True

    def resume(self) -> None:
        self._paused = False

    def status(self) -> dict:
        with self._lock:
            files = sorted((dict(s) for s in self._stats.values()), key=lambda s: s["path"])
        return {
            "enabled": True, "running": bool(self._thread and self._thread.is_alive()), "paused": self._paused,
            "directory": str(self.dir), "interval": self.interval, "files": files,
            "total_imported": sum(f["imported"] for f in files),
        }
