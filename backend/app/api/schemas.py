"""Request bodies and response serialisers for the API."""
from __future__ import annotations

from pydantic import BaseModel

from app.database.models import AlertHistoryRow, AlertRow, DetectionRuleRow, EventRow
from app.domain import AlertStatus, Severity
from app.mitre import techniques_for_rule


class AlertUpdate(BaseModel):
    status: AlertStatus
    note: str | None = None


class RuleUpdate(BaseModel):
    enabled: bool | None = None
    severity: Severity | None = None
    params: dict | None = None


def event_out(r: EventRow) -> dict:
    return {
        "id": r.id, "timestamp": r.timestamp.isoformat(), "source": r.source, "event_type": r.event_type,
        "severity": r.severity, "username": r.username, "source_ip": r.source_ip, "host": r.host,
        "service": r.service, "message": r.message, "raw": r.raw, "metadata": r.extra or {},
    }


def alert_out(r: AlertRow) -> dict:
    return {
        "id": r.id, "alert_id": r.alert_code, "rule_id": r.rule_id, "rule_name": r.rule_name,
        "severity": r.severity, "status": r.status, "description": r.description, "source_ip": r.source_ip,
        "username": r.username, "occurrences": r.occurrences, "window_minutes": r.window_minutes,
        "created_at": r.created_at.isoformat(), "last_seen": r.last_seen.isoformat(),
        "techniques": techniques_for_rule(r.rule_id),
    }


def history_out(h: AlertHistoryRow) -> dict:
    return {"from_status": h.from_status, "to_status": h.to_status, "note": h.note, "at": h.at.isoformat()}


def rule_out(r: DetectionRuleRow) -> dict:
    return {"id": r.id, "name": r.name, "description": r.description, "severity": r.severity,
            "event_types": r.event_types, "params": r.params, "enabled": r.enabled,
            "techniques": techniques_for_rule(r.id)}
