"""Alert lifecycle: creation, de-duplication, status management and history."""
from __future__ import annotations

from datetime import timedelta

from app.database.models import AlertRow
from app.database.repositories import AlertRepository
from app.domain import SEVERITY_RANK, AlertStatus, Detection, Severity, utcnow

_ALLOWED = {
    AlertStatus.OPEN: {AlertStatus.INVESTIGATING, AlertStatus.RESOLVED},
    AlertStatus.INVESTIGATING: {AlertStatus.RESOLVED, AlertStatus.OPEN},
    AlertStatus.RESOLVED: {AlertStatus.OPEN},
}


class InvalidTransition(ValueError):
    pass


class AlertManager:
    def __init__(self, alerts: AlertRepository, dedupe_window_minutes: int = 30):
        self.alerts = alerts
        self.dedupe = timedelta(minutes=dedupe_window_minutes)
        self.created: list[AlertRow] = []
        self.updated: list[AlertRow] = []

    def process(self, detections: list[Detection]) -> list[AlertRow]:
        out = []
        for d in detections:
            last_event = max(e.timestamp for e in d.events)
            existing = self.alerts.find_active_by_key(d.key, last_event - self.dedupe)
            ids = [e.id for e in d.events if e.id is not None]
            if existing:
                existing.occurrences = max(existing.occurrences, d.occurrences)
                if SEVERITY_RANK[d.severity] > SEVERITY_RANK[Severity(existing.severity)]:
                    existing.severity = d.severity.value
                existing.last_seen = max(existing.last_seen, last_event)
                self.alerts.link_events(existing.id, ids)
                self.updated.append(existing)
                out.append(existing)
                continue
            alert = self.alerts.create(
                rule_id=d.rule_id, rule_name=d.rule_name, severity=d.severity.value, status="OPEN", key=d.key,
                description=d.description, source_ip=d.source_ip, username=d.username,
                occurrences=d.occurrences, window_minutes=d.window_minutes,
                created_at=utcnow(), last_seen=last_event)
            self.alerts.add_history(alert.id, None, "OPEN", "Alert created by detection engine")
            self.alerts.link_events(alert.id, ids)
            self.created.append(alert)
            out.append(alert)
        return out

    def change_status(self, alert_id: int, new_status: AlertStatus, note: str | None = None) -> AlertRow:
        alert = self.alerts.get(alert_id)
        if alert is None:
            raise LookupError(f"Alert {alert_id} not found")
        current = AlertStatus(alert.status)
        if new_status not in _ALLOWED[current]:
            raise InvalidTransition(f"Cannot change status from {current.value} to {new_status.value}")
        alert.status = new_status.value
        self.alerts.add_history(alert.id, current.value, new_status.value, note)
        return alert
