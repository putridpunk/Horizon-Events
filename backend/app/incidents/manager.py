"""Incident lifecycle: automatic correlation of alerts, manual edits, status and audit trail."""
from __future__ import annotations

from datetime import timedelta

from app.alerts.manager import _ALLOWED, InvalidTransition
from app.database.models import AlertRow, IncidentRow
from app.database.repositories import IncidentRepository
from app.domain import SEVERITY_RANK, AlertStatus, Severity, utcnow

CORRELATION_WINDOW = timedelta(hours=24)


class IncidentManager:
    def __init__(self, repo: IncidentRepository):
        self.repo = repo

    # -- automatic correlation -------------------------------------------------------------
    def correlate(self, alerts: list[AlertRow]) -> None:
        """Attach alerts to incidents (creating them when needed). Safe to call repeatedly."""
        for alert in sorted(alerts, key=lambda a: (a.last_seen, a.id)):
            incident = self.repo.incident_for_alert(alert.id)
            if incident is not None:
                self._refresh(incident)
                continue
            if self.repo.is_excluded(alert.id) or not (alert.source_ip or alert.username):
                continue
            candidates = self.repo.candidates(alert.source_ip, alert.username,
                                              alert.last_seen - CORRELATION_WINDOW,
                                              alert.last_seen + CORRELATION_WINDOW)
            if candidates:
                incident = candidates[0]
            else:
                where = f"from {alert.source_ip}" if alert.source_ip else f"on account {alert.username}"
                incident = self.repo.create(title=f"{alert.rule_name} {where}", severity=alert.severity,
                                            status="OPEN", created_at=utcnow(), updated_at=utcnow(),
                                            last_activity=alert.last_seen)
                self.repo.add_history(incident.id, "created", f"Opened automatically from {alert.alert_code}")
            self.repo.link(incident.id, alert.id, "auto")
            self.repo.add_history(incident.id, "alert_added", f"{alert.alert_code} {alert.rule_name} (automatic)")
            self._refresh(incident)

    def backfill(self) -> int:
        """Group existing alerts that have no incident yet. Returns how many alerts were considered."""
        pending = self.repo.unassigned_alerts()
        self.correlate(pending)
        return len(pending)

    def _refresh(self, incident: IncidentRow) -> None:
        alerts = self.repo.alerts_of(incident.id)
        if not alerts:
            return
        incident.severity = max((a.severity for a in alerts), key=lambda s: SEVERITY_RANK[Severity(s)])
        incident.last_activity = max(a.last_seen for a in alerts)
        incident.updated_at = utcnow()

    # -- analyst actions -------------------------------------------------------------------
    def _get(self, incident_id: int) -> IncidentRow:
        incident = self.repo.get(incident_id)
        if incident is None:
            raise LookupError(f"Incident {incident_id} not found")
        return incident

    def change_status(self, incident_id: int, new_status: AlertStatus, note: str | None = None) -> IncidentRow:
        incident = self._get(incident_id)
        current = AlertStatus(incident.status)
        if new_status not in _ALLOWED[current]:
            raise InvalidTransition(f"Cannot change status from {current.value} to {new_status.value}")
        incident.status = new_status.value
        incident.updated_at = utcnow()
        self.repo.add_history(incident.id, "status_changed", note, current.value, new_status.value)
        return incident

    def set_title(self, incident_id: int, title: str) -> IncidentRow:
        title = (title or "").strip()
        if not title:
            raise ValueError("Title must not be empty")
        incident = self._get(incident_id)
        self.repo.add_history(incident.id, "title_changed", f"{incident.title} -> {title}")
        incident.title, incident.updated_at = title, utcnow()
        return incident

    def add_note(self, incident_id: int, text: str) -> IncidentRow:
        text = (text or "").strip()
        if not text:
            raise ValueError("Note must not be empty")
        incident = self._get(incident_id)
        self.repo.add_history(incident.id, "note", text)
        incident.updated_at = utcnow()
        return incident

    def add_alert(self, incident_id: int, alert_id: int) -> IncidentRow:
        incident = self._get(incident_id)
        alert = self.repo.get_alert(alert_id)
        if alert is None:
            raise LookupError(f"Alert {alert_id} not found")
        previous = self.repo.incident_for_alert(alert_id)
        if previous is not None and previous.id == incident.id:
            return incident
        if previous is not None:
            self.repo.unlink(alert_id)
            self.repo.add_history(previous.id, "alert_removed", f"{alert.alert_code} moved to {incident.code}")
            self._refresh(previous)
        self.repo.unexclude(alert_id)
        self.repo.link(incident.id, alert_id, "manual")
        self.repo.add_history(incident.id, "alert_added", f"{alert.alert_code} {alert.rule_name} (manual)")
        self._refresh(incident)
        return incident

    def remove_alert(self, incident_id: int, alert_id: int) -> IncidentRow:
        incident = self._get(incident_id)
        current = self.repo.incident_for_alert(alert_id)
        if current is None or current.id != incident.id:
            raise LookupError(f"Alert {alert_id} is not in {incident.code}")
        alert = self.repo.get_alert(alert_id)
        self.repo.unlink(alert_id)
        self.repo.exclude(alert_id)
        self.repo.add_history(incident.id, "alert_removed", f"{alert.alert_code} removed by analyst")
        self._refresh(incident)
        return incident

    def merge(self, source_id: int, into_id: int) -> IncidentRow:
        if source_id == into_id:
            raise ValueError("An incident cannot be merged into itself")
        source, target = self._get(source_id), self._get(into_id)
        if target.status == "RESOLVED":
            raise ValueError("Cannot merge into a resolved incident")
        alerts = self.repo.alerts_of(source.id)
        for alert in alerts:
            self.repo.unlink(alert.id)
            self.repo.link(target.id, alert.id, "manual")
        self.repo.add_history(target.id, "merged", f"{len(alerts)} alert(s) merged in from {source.code}")
        self.repo.add_history(source.id, "merged", f"Merged into {target.code}")
        if source.status != "RESOLVED":
            self.repo.add_history(source.id, "status_changed", "Closed by merge", source.status, "RESOLVED")
            source.status = "RESOLVED"
        source.updated_at = utcnow()
        self._refresh(target)
        return target
