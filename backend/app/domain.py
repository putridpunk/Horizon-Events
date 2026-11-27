"""Pure domain types shared by the pipeline. No framework imports."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


SEVERITY_RANK = {Severity.low: 1, Severity.medium: 2, Severity.high: 3, Severity.critical: 4}


class EventType(str, Enum):
    authentication_success = "authentication_success"
    authentication_failure = "authentication_failure"
    unknown_user = "unknown_user"
    account_lockout = "account_lockout"
    privilege_escalation = "privilege_escalation"
    service_failure = "service_failure"
    service_start = "service_start"
    log_cleared = "log_cleared"
    service_installed = "service_installed"
    scheduled_task_created = "scheduled_task_created"
    remote_login = "remote_login"
    explicit_credentials = "explicit_credentials"
    ntlm_logon = "ntlm_logon"
    powershell_script = "powershell_script"
    usb_device = "usb_device"
    generic = "generic"


class AlertStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"


@dataclass
class Event:
    timestamp: datetime
    source: str
    event_type: EventType
    severity: Severity
    message: str
    raw: str
    username: str | None = None
    source_ip: str | None = None
    host: str | None = None
    service: str | None = None
    metadata: dict = field(default_factory=dict)
    id: int | None = None  # set once persisted

    def fingerprint(self) -> str:
        data = f"{self.source}|{self.timestamp.isoformat()}|{self.raw}"
        return hashlib.sha256(data.encode("utf-8", "replace")).hexdigest()


@dataclass
class Detection:
    rule_id: str
    rule_name: str
    severity: Severity
    description: str
    events: list[Event]
    source_ip: str | None
    username: str | None
    occurrences: int
    window_minutes: int | None
    key: str


def utcnow() -> datetime:
    """Naive UTC 'now' (the app stores naive UTC timestamps)."""
    from datetime import timezone
    return datetime.now(timezone.utc).replace(tzinfo=None)
