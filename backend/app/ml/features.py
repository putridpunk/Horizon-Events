"""Window feature extraction for anomaly detection. Pure Python."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from app.domain import Event, EventType

FEATURE_NAMES = ["events", "failures", "successes", "distinct_users", "distinct_failed_users",
                 "failure_ratio", "off_hours"]

_FAILURES = {EventType.authentication_failure, EventType.unknown_user}


def hour_start(ts: datetime) -> datetime:
    return ts.replace(minute=0, second=0, microsecond=0)


def group_windows(events: list[Event]) -> dict[tuple[str, datetime], list[Event]]:
    """Group events by (source IP, hour). Events without an IP are ignored."""
    windows: dict[tuple[str, datetime], list[Event]] = defaultdict(list)
    for e in events:
        if e.source_ip:
            windows[(e.source_ip, hour_start(e.timestamp))].append(e)
    return dict(windows)


def window_features(events: list[Event]) -> list[float]:
    n = len(events)
    failures = sum(e.event_type in _FAILURES for e in events)
    successes = sum(e.event_type == EventType.authentication_success for e in events)
    hour = events[0].timestamp.hour
    return [
        float(n), float(failures), float(successes),
        float(len({e.username for e in events if e.username})),
        float(len({e.username for e in events if e.username and e.event_type in _FAILURES})),
        failures / n,
        0.0 if 8 <= hour < 18 else 1.0,
    ]
