"""Convert parser output into the common Event representation."""
from __future__ import annotations

from app.domain import Event, EventType, Severity

_DEFAULT_SEVERITY = {
    EventType.authentication_success: Severity.low,
    EventType.authentication_failure: Severity.medium,
    EventType.unknown_user: Severity.medium,
    EventType.account_lockout: Severity.high,
    EventType.privilege_escalation: Severity.high,
    EventType.service_failure: Severity.medium,
    EventType.service_start: Severity.low,
    EventType.generic: Severity.low,
}


def normalize(parsed: dict, source: str) -> Event:
    try:
        etype = EventType(parsed.get("event_hint", "generic"))
    except ValueError:
        etype = EventType.generic
    try:
        sev = Severity(str(parsed["severity"]).lower()) if parsed.get("severity") else _DEFAULT_SEVERITY[etype]
    except ValueError:
        sev = _DEFAULT_SEVERITY[etype]
    meta = {k: parsed[k] for k in ("process", "level") if parsed.get(k)}
    return Event(
        timestamp=parsed["timestamp"], source=source, event_type=etype, severity=sev,
        message=parsed.get("message", ""), raw=parsed.get("raw", ""),
        username=parsed.get("username") or None, source_ip=parsed.get("source_ip") or None,
        host=parsed.get("host") or None, service=parsed.get("service") or None, metadata=meta,
    )
