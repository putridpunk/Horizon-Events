"""Scan files and folders the user picked, and turn every detection into an alert."""
from __future__ import annotations

import hashlib
import logging
import os
import threading
from datetime import datetime
from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.alerts.manager import AlertManager
from app.database.repositories import AlertRepository, EventRepository
from app.database.scan_models import ScanRow
from app.domain import Detection, Event, EventType, Severity, utcnow
from app.live.bus import bus
from app.notifications.service import dispatch_async
from app.scanning import defender
from app.scanning.defender import CLEAN, ERROR, THREAT, Finding, ScanOutcome
from app.services.ingestion import ensure_default_rules

log = logging.getLogger(__name__)

RULE_ID = "HZ-008"
RULE_NAME = "Malware detected"
MAX_TARGETS = 50
MAX_HASH_BYTES = 512 * 1024 * 1024  # larger files are reported without a hash


class ScanBusy(RuntimeError):
    """Another scan is still running."""


def validate_paths(paths) -> list[str]:
    """Absolute, existing, local paths only. UNC and device paths are refused: opening them would make Windows
    authenticate to whatever host the path names. Raises ValueError with a message for the user."""
    if not isinstance(paths, list) or not paths:
        raise ValueError("Choose at least one file or folder.")
    if len(paths) > MAX_TARGETS:
        raise ValueError(f"Choose at most {MAX_TARGETS} items at a time.")
    clean: list[str] = []
    for raw in paths:
        if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
            raise ValueError("A chosen path is not valid.")
        if raw.startswith(("\\\\", "//")):
            raise ValueError(f"Network and device paths cannot be scanned: {raw}")
        if not os.path.isabs(raw):
            raise ValueError(f"The path must be absolute: {raw}")
        path = os.path.normpath(raw)
        if not os.path.exists(path):
            raise ValueError(f"Not found: {path}")
        if path not in clean:
            clean.append(path)
    return clean


def sha256_file(path: str, limit: int = MAX_HASH_BYTES) -> str | None:
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > limit:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:  # the file may have been removed or locked since the scan
        return None


def record_detection(session: Session, finding: Finding, sha256: str | None, now: datetime | None = None,
                     created: list[int] | None = None) -> int:
    """Store the detection as an event and raise (or update) its alert. Returns the alert id.
    The id of a newly created alert is also appended to `created`, so the caller can announce it."""
    now = now or utcnow()
    message = f"Malware detected: {finding.threat} in {finding.path}"
    event = Event(
        timestamp=now, source="file_scan", event_type=EventType.generic, severity=Severity.critical,
        message=message, raw=f"{now.isoformat()}|{finding.path}|{finding.threat}|{sha256 or ''}",
        metadata={"path": finding.path, "threat": finding.threat, "sha256": sha256, "engine": "Microsoft Defender"})
    stored = EventRepository(session).add_many([event])
    ensure_default_rules(session)
    detection = Detection(
        rule_id=RULE_ID, rule_name=RULE_NAME, severity=Severity.critical,
        description=f"Microsoft Defender reported {finding.threat} in {finding.path}."
                    + (f" SHA-256 {sha256}." if sha256 else ""),
        events=stored, source_ip=None, username=None, occurrences=1, window_minutes=None,
        key=f"{RULE_ID}|{sha256 or finding.path}|{finding.threat}")
    manager = AlertManager(AlertRepository(session))
    alert = manager.process([detection])[0]
    if created is not None and manager.created:
        created.append(alert.id)
    return alert.id


class ScanService:
    def __init__(self, session_factory: Callable[[], Session], scanner=defender.scan_path, mitigation=None):
        self.session_factory = session_factory
        self.scanner = scanner
        self.mitigation = mitigation  # optional: told about each malware alert (may quarantine it)
        self._lock = threading.Lock()
        self._active: threading.Thread | None = None
        with session_factory() as session:  # a scan cannot survive a restart: close any left open
            for row in session.scalars(select(ScanRow).where(ScanRow.status == "running")):
                row.status, row.finished_at, row.error = "failed", utcnow(), "The app was closed during the scan."
            session.commit()

    @staticmethod
    def engine_status() -> dict:
        available = defender.find_defender() is not None
        return {"enabled": True, "engine": "Microsoft Defender", "available": available,
                "message": "" if available else "Microsoft Defender was not found on this computer."}

    def start(self, paths) -> dict:
        targets = validate_paths(paths)
        with self._lock:
            if self._active is not None and self._active.is_alive():
                raise ScanBusy("A scan is already running.")
            with self.session_factory() as session:
                row = ScanRow(created_at=utcnow(), status="running", targets=targets, results=[])
                session.add(row)
                session.commit()
                scan_id, snapshot = row.id, row.as_dict()
            self._active = threading.Thread(target=self._run, args=(scan_id, targets), name="file-scan", daemon=True)
            self._active.start()
        return snapshot

    def wait(self, timeout: float = 30.0) -> None:
        thread = self._active
        if thread is not None:
            thread.join(timeout)

    def _run(self, scan_id: int, targets: list[str]) -> None:
        try:
            for target in targets:
                outcome = self.scanner(target)
                self._store(scan_id, target, outcome)
            self._finish(scan_id, "completed", None)
        except Exception as exc:  # never leave a scan "running" forever
            log.exception("file scan %s failed", scan_id)
            self._finish(scan_id, "failed", f"{type(exc).__name__}: {exc}")

    def _store(self, scan_id: int, target: str, outcome: ScanOutcome) -> None:
        with self.session_factory() as session:
            threats, announce = [], []
            if outcome.status == THREAT:
                for finding in outcome.findings:
                    sha = sha256_file(finding.path)
                    alert_id = record_detection(session, finding, sha, created=announce)
                    if self.mitigation is not None:
                        try:
                            self.mitigation.on_malware_alert(session, alert_id, finding.path, sha)
                        except Exception:  # a mitigation problem must never lose the detection
                            log.exception("mitigation after a malware alert failed")
                    threats.append({"threat": finding.threat, "path": finding.path, "sha256": sha, "alert_id": alert_id})
            row = session.get(ScanRow, scan_id)
            row.results = [*row.results, {"path": target, "status": outcome.status if outcome.status in
                                          (CLEAN, THREAT) else ERROR, "message": outcome.message, "threats": threats}]
            session.commit()
            dispatch_async(session.get_bind(), announce)
            bus.publish("scans", *(["alerts", "events"] if threats else []))

    def _finish(self, scan_id: int, status: str, error: str | None) -> None:
        with self.session_factory() as session:
            row = session.get(ScanRow, scan_id)
            row.status, row.error, row.finished_at = status, error, utcnow()
            session.commit()

    def get(self, scan_id: int) -> dict | None:
        with self.session_factory() as session:
            row = session.get(ScanRow, scan_id)
            return row.as_dict() if row else None

    def recent(self, limit: int = 10) -> list[dict]:
        with self.session_factory() as session:
            rows = session.scalars(select(ScanRow).order_by(ScanRow.id.desc()).limit(limit))
            return [r.as_dict() for r in rows]
