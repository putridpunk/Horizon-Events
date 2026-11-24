"""Mitigation: propose steps for alerts, carry them out when approved (or automatically, where allowed), undo them."""
from __future__ import annotations

import json
import logging
import threading
from datetime import timedelta
from pathlib import Path
from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.collector_models import get_setting, set_setting
from app.database.mitigation_models import (BLOCK_IP, DISMISSED, DONE, FAILED, QUARANTINE, RUNNING, SUGGESTED, UNDONE,
                                            MitigationRow)
from app.database.models import AlertRow
from app.database.repositories import AlertRepository
from app.domain import utcnow
from app.mitigation import firewall, quarantine
from app.mitigation.elevate import run_elevated
from app.system.winutil import run_command

log = logging.getLogger(__name__)

MODES = ("off", "ask", "auto")
AUTOMATIC_ALLOWED = (QUARANTINE,)  # blocking needs administrator rights, so it is never automatic
DEFAULTS = {"block_ip": "ask", "quarantine_file": "ask", "block_private": False, "block_days": 7, "allowlist": []}
SETTING_KEY = "mitigation"


class MitigationError(ValueError):
    """A request that cannot be carried out; the message is shown to the user."""


# ---- settings (readable in every mode; stored in the app settings table) ---------------------------------------
def load_settings(session: Session) -> dict:
    stored = {}
    try:
        stored = json.loads(get_setting(session, SETTING_KEY, "{}") or "{}")
    except ValueError:
        pass
    return {**DEFAULTS, **{k: v for k, v in stored.items() if k in DEFAULTS}}


def save_settings(session: Session, patch: dict) -> dict:
    current = load_settings(session)
    for key, value in patch.items():
        if key not in DEFAULTS:
            raise MitigationError(f"Unknown setting: {key}")
        if key in ("block_ip", "quarantine_file"):
            if value not in MODES:
                raise MitigationError("The mode must be off, ask or auto.")
            if value == "auto" and key not in AUTOMATIC_ALLOWED:
                raise MitigationError("Blocking an address needs your approval each time, so it cannot be automatic.")
        elif key == "block_private":
            if not isinstance(value, bool):
                raise MitigationError("block_private must be true or false.")
        elif key == "block_days":
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 365:
                raise MitigationError("Blocks must last between 1 and 365 days.")
        elif key == "allowlist":
            if not isinstance(value, list):
                raise MitigationError("The allowlist must be a list.")
            try:
                firewall.parse_networks(value)
            except ValueError as exc:
                raise MitigationError(str(exc)) from exc
            value = [str(v).strip() for v in value if str(v).strip()]
        current[key] = value
    set_setting(session, SETTING_KEY, json.dumps(current))
    return current


class MitigationService:
    def __init__(self, session_factory: Callable[[], Session], quarantine_dir: Path, elevator=run_elevated,
                 runner=run_command, own_ips: Callable[[], set[str]] = firewall.own_addresses):
        self.session_factory = session_factory
        self.quarantine_dir = Path(quarantine_dir)
        self.elevator, self.runner, self.own_ips = elevator, runner, own_ips
        self._threads: list[threading.Thread] = []
        with session_factory() as session:  # an action cannot survive a restart: close any left running
            for row in session.scalars(select(MitigationRow).where(MitigationRow.status == RUNNING)):
                row.status, row.finished_at = FAILED, utcnow()
                row.detail = {**(row.detail or {}), "message": "The app was closed before this finished."}
            session.commit()

    # ---- proposals ---------------------------------------------------------------------------------------------
    def for_alert(self, session: Session, alert: AlertRow) -> dict:
        """The actions on this alert (creating proposals that are due) and the ones that were not proposed, with why."""
        settings = load_settings(session)
        skipped: list[dict] = []
        if alert.rule_id in firewall.BLOCK_RULES and settings["block_ip"] != "off":
            self._propose_block(session, alert, settings, skipped)
        if alert.rule_id == "HZ-008" and settings["quarantine_file"] != "off":
            self._propose_quarantine(session, alert, skipped)
        session.flush()
        rows = session.scalars(select(MitigationRow).where(MitigationRow.alert_id == alert.id)
                               .order_by(MitigationRow.id)).all()
        now = utcnow()
        return {"actions": [r.as_dict(now) for r in rows], "skipped": skipped}

    def _existing(self, session: Session, kind: str, target: str, alert_id: int | None = None) -> list[MitigationRow]:
        stmt = select(MitigationRow).where(MitigationRow.kind == kind, MitigationRow.target == target)
        if alert_id is not None:
            stmt = stmt.where(MitigationRow.alert_id == alert_id)
        return list(session.scalars(stmt))

    def _propose_block(self, session: Session, alert: AlertRow, settings: dict, skipped: list) -> None:
        ip = alert.source_ip
        if any(r.alert_id == alert.id for r in self._existing(session, BLOCK_IP, ip or "")):
            return
        if any(r.status in (DONE, RUNNING) for r in self._existing(session, BLOCK_IP, ip or "")):
            skipped.append({"kind": BLOCK_IP, "target": ip, "reason": "This address is already blocked."})
            return
        reason = firewall.blockable_reason(ip, settings["allowlist"], settings["block_private"], self.own_ips())
        if reason:
            skipped.append({"kind": BLOCK_IP, "target": ip, "reason": reason})
            return
        session.add(MitigationRow(alert_id=alert.id, kind=BLOCK_IP, target=ip, status=SUGGESTED, created_at=utcnow(),
                                  detail={}))

    def _malware_path(self, session: Session, alert_id: int) -> tuple[str | None, str | None]:
        for event in AlertRepository(session).linked_events(alert_id):
            extra = event.extra or {}
            if extra.get("path"):
                return extra["path"], extra.get("sha256")
        return None, None

    def _propose_quarantine(self, session: Session, alert: AlertRow, skipped: list) -> None:
        path, sha = self._malware_path(session, alert.id)
        if not path:
            return
        if self._existing(session, QUARANTINE, path, alert.id):
            return
        if not Path(path).is_file():
            skipped.append({"kind": QUARANTINE, "target": path, "reason": "The file is no longer there."})
            return
        session.add(MitigationRow(alert_id=alert.id, kind=QUARANTINE, target=path, status=SUGGESTED,
                                  created_at=utcnow(), detail={"sha256": sha}))

    def on_malware_alert(self, session: Session, alert_id: int, path: str, sha256: str | None) -> None:
        """Called by the file scanner right after it raises an alert. In Automatic mode the file is quarantined now."""
        mode = load_settings(session)["quarantine_file"]
        if mode == "off" or self._existing(session, QUARANTINE, path, alert_id):
            return
        row = MitigationRow(alert_id=alert_id, kind=QUARANTINE, target=path, status=SUGGESTED, created_at=utcnow(),
                            detail={"sha256": sha256})
        session.add(row)
        session.flush()
        if mode == "auto":
            row.automatic = True
            self._quarantine(row)

    # ---- acting ------------------------------------------------------------------------------------------------
    def approve(self, mitigation_id: int) -> dict:
        with self.session_factory() as session:
            row = self._get(session, mitigation_id)
            if row.status not in (SUGGESTED, FAILED):
                raise MitigationError(f"This action is already {row.status}.")
            row.status, row.finished_at = RUNNING, None
            row.detail = {**(row.detail or {}), "message": "Waiting for you in the Windows permission prompt…"
                          if row.kind == BLOCK_IP else "Moving the file…", "op": "do"}
            session.commit()
            snapshot = row.as_dict(utcnow())
        self._spawn(mitigation_id)
        return snapshot

    def undo(self, mitigation_id: int) -> dict:
        with self.session_factory() as session:
            row = self._get(session, mitigation_id)
            if row.status != DONE:
                raise MitigationError("Only an action that was carried out can be undone.")
            row.status, row.finished_at = RUNNING, None
            row.detail = {**(row.detail or {}), "message": "Undoing…", "op": "undo"}
            session.commit()
            snapshot = row.as_dict(utcnow())
        self._spawn(mitigation_id)
        return snapshot

    def dismiss(self, mitigation_id: int) -> dict:
        with self.session_factory() as session:
            row = self._get(session, mitigation_id)
            if row.status not in (SUGGESTED, FAILED):
                raise MitigationError(f"This action is already {row.status}.")
            row.status, row.finished_at = DISMISSED, utcnow()
            session.commit()
            return row.as_dict(utcnow())

    def history(self, limit: int = 100) -> list[dict]:
        with self.session_factory() as session:
            rows = session.scalars(select(MitigationRow).order_by(MitigationRow.id.desc()).limit(limit))
            now = utcnow()
            return [r.as_dict(now) for r in rows]

    def wait(self, timeout: float = 30.0) -> None:
        for thread in list(self._threads):
            thread.join(timeout)

    # ---- internals ---------------------------------------------------------------------------------------------
    @staticmethod
    def _get(session: Session, mitigation_id: int) -> MitigationRow:
        row = session.get(MitigationRow, mitigation_id)
        if row is None:
            raise LookupError("Action not found")
        return row

    def _spawn(self, mitigation_id: int) -> None:
        thread = threading.Thread(target=self._run, args=(mitigation_id,), name="mitigation", daemon=True)
        self._threads = [t for t in self._threads if t.is_alive()] + [thread]
        thread.start()

    def _run(self, mitigation_id: int) -> None:
        with self.session_factory() as session:
            row = session.get(MitigationRow, mitigation_id)
            try:
                if (row.detail or {}).get("op") == "undo":
                    self._undo(session, row)
                elif row.kind == BLOCK_IP:
                    self._block(session, row)
                else:
                    self._quarantine(row)
            except Exception as exc:  # never leave an action "running" forever
                log.exception("mitigation %s failed", mitigation_id)
                self._fail(row, f"{type(exc).__name__}: {exc}", undo=(row.detail or {}).get("op") == "undo")
            session.commit()

    @staticmethod
    def _fail(row: MitigationRow, message: str, undo: bool = False) -> None:
        # a failed undo leaves the action in force; a failed action simply did not happen
        row.status, row.finished_at = (DONE if undo else FAILED), utcnow()
        row.detail = {**(row.detail or {}), "message": message}

    def _block(self, session: Session, row: MitigationRow) -> None:
        settings = load_settings(session)
        reason = firewall.blockable_reason(row.target, settings["allowlist"], settings["block_private"], self.own_ips())
        if reason:
            return self._fail(row, reason)
        _, message = self.elevator(firewall.netsh(), firewall.add_rule_args(row.target))
        if firewall.rule_exists(row.target, self.runner):
            now = utcnow()
            row.status, row.finished_at = DONE, now
            row.expires_at = now + timedelta(days=settings["block_days"])
            row.detail = {**(row.detail or {}), "message": f"Blocked until {row.expires_at:%Y-%m-%d}."}
        else:
            self._fail(row, message or "The firewall rule was not created.")

    def _quarantine(self, row: MitigationRow) -> None:
        try:
            dest = quarantine.quarantine(row.target, self.quarantine_dir, row.id)
        except quarantine.QuarantineError as exc:
            return self._fail(row, str(exc))
        row.status, row.finished_at = DONE, utcnow()
        row.detail = {**(row.detail or {}), "quarantine_path": dest, "message": "Moved to quarantine."}

    def _undo(self, session: Session, row: MitigationRow) -> None:
        if row.kind == BLOCK_IP:
            _, message = self.elevator(firewall.netsh(), firewall.delete_rule_args(row.target))
            if firewall.rule_exists(row.target, self.runner):
                return self._fail(row, message or "The firewall rule is still there.", undo=True)
            row.detail = {**(row.detail or {}), "message": "Block removed."}
        else:
            try:
                quarantine.restore((row.detail or {}).get("quarantine_path", ""), row.target)
            except quarantine.QuarantineError as exc:
                return self._fail(row, str(exc), undo=True)
            row.detail = {**(row.detail or {}), "message": "Restored to its original place."}
        row.status, row.finished_at = UNDONE, utcnow()
