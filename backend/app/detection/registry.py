"""Registry of all detection rules (rule-based and ML)."""
from __future__ import annotations

from app.detection.anomaly import AnomalousIpActivity
from app.detection.rules import (AccountLockouts, PrivilegeEscalation, RepeatedLoginFailures, Rule, ServiceFailures,
                                 UnknownUsers, UnusualLoginHours)

RULE_CLASSES: dict[str, type[Rule]] = {c.id: c for c in (
    RepeatedLoginFailures, UnusualLoginHours, UnknownUsers, PrivilegeEscalation, ServiceFailures, AccountLockouts,
    AnomalousIpActivity)}

DEFAULT_RULES: list[dict] = [
    {"id": c.id, "name": c.name, "description": c.description, "severity": c.severity.value,
     "event_types": [t.value for t in c.event_types], "params": dict(c.default_params), "enabled": True}
    for c in RULE_CLASSES.values()]


def build_rule(defn: dict) -> Rule | None:
    """Build a Rule from a stored definition (dict with id, severity, params). None if unknown."""
    cls = RULE_CLASSES.get(defn["id"])
    return cls(severity=defn.get("severity"), params=defn.get("params")) if cls else None
