"""Try a rule on the past: what alerts would it have raised over the last few days? Nothing is stored, so rules can be
tuned (a threshold, a window, a list of accounts to ignore) before they are switched on."""
from __future__ import annotations

from collections import Counter
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import AlertRow
from app.database.repositories import EventRepository
from app.detection.registry import build_rule
from app.domain import SEVERITY_RANK, Severity, utcnow

MAX_DAYS = 90
MAX_EVENTS = 50_000
MAX_SHOWN = 100
NOT_REPLAYABLE = {"HZ-008": "Malware detections come from file scans, not from logs, so they cannot be tried on past events."}


class ReplayError(ValueError):
    """A rule that cannot be tried; the message is shown to the user."""


def replay(session: Session, definition: dict, days: int, now=None) -> dict:
    """`definition` has id, name, description, severity and params, as stored for a rule."""
    if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= MAX_DAYS:
        raise ReplayError(f"Choose between 1 and {MAX_DAYS} days.")
    if definition["id"] in NOT_REPLAYABLE:
        raise ReplayError(NOT_REPLAYABLE[definition["id"]])
    rule = build_rule(definition)
    if rule is None:
        raise ReplayError("This rule cannot be built from its settings.")
    now = now or utcnow()
    since = now - timedelta(days=days)
    repo = EventRepository(session)
    events = repo.events_in_window(rule.event_types, since, now)
    truncated = len(events) > MAX_EVENTS
    if truncated:
        events = events[-MAX_EVENTS:]  # the newest
    detections = rule.evaluate(events, repo)
    detections.sort(key=lambda d: (-SEVERITY_RANK[d.severity], -d.occurrences))
    keys = [d.key for d in detections]
    known = set(session.scalars(select(AlertRow.key).where(AlertRow.key.in_(keys), AlertRow.last_seen >= since))) if keys else set()
    shown = []
    for d in detections[:MAX_SHOWN]:
        times = sorted(e.timestamp for e in d.events)
        shown.append({
            "key": d.key, "severity": d.severity.value, "description": d.description, "source_ip": d.source_ip,
            "username": d.username, "occurrences": d.occurrences, "window_minutes": d.window_minutes,
            "first_event": times[0].isoformat() if times else None, "last_event": times[-1].isoformat() if times else None,
            "event_ids": [e.id for e in d.events if e.id is not None][:10], "already_alerted": d.key in known})
    return {
        "rule_id": definition["id"], "days": days, "events_scanned": len(events), "truncated": truncated,
        "would_alert": len(detections), "already_alerted": sum(1 for d in detections if d.key in known),
        "by_severity": {s.value: sum(1 for d in detections if d.severity is s) for s in Severity},
        "top_sources": [{"value": v, "count": c} for v, c in
                        Counter(d.source_ip or d.username for d in detections if d.source_ip or d.username).most_common(5)],
        "detections": shown, "shown": len(shown),
        "note": "Replay treats the whole period as one batch. Live detection judges events as they arrive, so the "
                "alerts you would really have received can be split differently, but the same activity is flagged.",
    }
