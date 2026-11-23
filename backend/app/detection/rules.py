"""Detection rules. Pure Python: rules read events through the EventHistory protocol only."""
from __future__ import annotations

from abc import ABC, abstractmethod
from bisect import bisect_right
from collections import Counter, defaultdict
from datetime import timedelta
from typing import Protocol

from app.domain import Detection, Event, EventType, Severity


class EventHistory(Protocol):
    def events_in_window(self, event_types, since, until, source_ip=None, username=None, service=None) -> list[Event]: ...


def _best_window(events: list[Event], anchor_ids: set, window: timedelta) -> list[Event]:
    """Largest set of events inside `window`, ending at an anchor (a newly ingested) event."""
    events = sorted(events, key=lambda e: e.timestamp)
    times = [e.timestamp for e in events]
    best: list[Event] = []
    for i, e in enumerate(events):
        if e.id not in anchor_ids:
            continue
        lo = bisect_right(times, e.timestamp - window)
        hi = bisect_right(times, e.timestamp)
        if hi - lo > len(best):
            best = events[lo:hi]
    return best


def _common(values):
    vals = [v for v in values if v]
    return Counter(vals).most_common(1)[0][0] if vals else None


class Rule(ABC):
    id: str
    name: str
    description: str
    severity: Severity
    event_types: list[EventType]
    default_params: dict = {}

    def __init__(self, severity: Severity | str | None = None, params: dict | None = None):
        if severity is not None:
            self.severity = Severity(severity)
        self.params = {**self.default_params, **(params or {})}

    @abstractmethod
    def evaluate(self, new_events: list[Event], history: EventHistory) -> list[Detection]: ...

    def _detection(self, events: list[Event], *, severity: Severity | None = None, ip=None, user=None,
                   window: int | None = None, description: str | None = None) -> Detection:
        return Detection(
            rule_id=self.id, rule_name=self.name, severity=severity or self.severity,
            description=description or self.description, events=events, source_ip=ip, username=user,
            occurrences=len(events), window_minutes=window, key=f"{self.id}|{ip or ''}|{user or ''}")

    def _windowed_groups(self, new_events, history, group_key, window_minutes: int, min_count: int):
        """Yield (group, best_window_events) for groups reaching min_count within the window."""
        window = timedelta(minutes=window_minutes)
        groups = defaultdict(list)
        for e in new_events:
            if e.event_type in self.event_types and group_key(e) is not None:
                groups[group_key(e)].append(e)
        for gk, evs in groups.items():
            ids = {e.id for e in evs}
            lo = min(e.timestamp for e in evs) - window
            hi = max(e.timestamp for e in evs)
            hist = history.events_in_window(self.event_types, lo, hi, **self._scope(gk))
            best = _best_window(hist, ids, window)
            if len(best) >= min_count:
                yield gk, best

    def _scope(self, group_key) -> dict:
        return {}


class RepeatedLoginFailures(Rule):
    id = "HZ-001"
    name = "Repeated login failures"
    description = "An unusually high number of failed authentication attempts was detected."
    severity = Severity.high
    event_types = [EventType.authentication_failure]
    default_params = {"threshold": 5, "critical_threshold": 10, "window_minutes": 5}

    def _scope(self, gk):
        return {"source_ip": gk}

    def evaluate(self, new_events, history):
        p = self.params
        out = []
        for ip, evs in self._windowed_groups(new_events, history, lambda e: e.source_ip,
                                             p["window_minutes"], p["threshold"]):
            sev = Severity.critical if len(evs) >= p["critical_threshold"] else self.severity
            out.append(self._detection(evs, severity=sev, ip=ip, user=_common(e.username for e in evs),
                                       window=p["window_minutes"]))
        return out


class UnusualLoginHours(Rule):
    id = "HZ-002"
    name = "Unusual login hours"
    description = "A successful login occurred outside the configured working hours."
    severity = Severity.medium
    event_types = [EventType.authentication_success]
    default_params = {"work_start": 8, "work_end": 18, "weekends": True}

    def evaluate(self, new_events, history):
        p = self.params
        groups = defaultdict(list)
        for e in new_events:
            if e.event_type not in self.event_types:
                continue
            off_hours = not (p["work_start"] <= e.timestamp.hour < p["work_end"])
            weekend = p["weekends"] and e.timestamp.weekday() >= 5
            if off_hours or weekend:
                groups[(e.source_ip, e.username)].append(e)
        return [self._detection(evs, ip=ip, user=user) for (ip, user), evs in groups.items()]


class UnknownUsers(Rule):
    id = "HZ-003"
    name = "Unknown users"
    description = "Authentication was attempted using an account that does not exist."
    severity = Severity.medium
    event_types = [EventType.unknown_user]
    default_params = {"ip_threshold": 3, "window_minutes": 5}

    def evaluate(self, new_events, history):
        p = self.params
        out, seen = [], set()
        for ip, evs in self._windowed_groups(new_events, history, lambda e: e.source_ip,
                                             p["window_minutes"], p["ip_threshold"]):
            seen.add(ip)
            users = {e.username for e in evs if e.username}
            out.append(self._detection(
                evs, severity=Severity.high, ip=ip, user=next(iter(users)) if len(users) == 1 else None,
                window=p["window_minutes"],
                description="Repeated authentication attempts against nonexistent accounts were detected."))
        singles = defaultdict(list)
        for e in new_events:
            if e.event_type in self.event_types and e.source_ip not in seen:
                singles[(e.source_ip, e.username)].append(e)
        out.extend(self._detection(evs, ip=ip, user=user) for (ip, user), evs in singles.items())
        return out


class PrivilegeEscalation(Rule):
    id = "HZ-004"
    name = "Privilege escalation events"
    description = "A privilege change was performed by an account that is not on the allowlist."
    severity = Severity.high
    event_types = [EventType.privilege_escalation]
    default_params = {"allowlist": ["root", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"]}

    def evaluate(self, new_events, history):
        allow = {a.lower() for a in self.params["allowlist"]}
        groups = defaultdict(list)
        for e in new_events:
            if e.event_type in self.event_types and (e.username or "").lower() not in allow:
                groups[(e.source_ip, e.username)].append(e)
        return [self._detection(evs, ip=ip, user=user) for (ip, user), evs in groups.items()]


class ServiceFailures(Rule):
    id = "HZ-005"
    name = "Service failures"
    description = "A service or application failed repeatedly in a short period."
    severity = Severity.medium
    event_types = [EventType.service_failure]
    default_params = {"threshold": 3, "window_minutes": 10}

    def _scope(self, gk):
        return {"service": gk}

    def evaluate(self, new_events, history):
        p = self.params
        out = []
        for svc, evs in self._windowed_groups(new_events, history, lambda e: e.service,
                                              p["window_minutes"], p["threshold"]):
            d = self._detection(evs, user=None, window=p["window_minutes"],
                                description=f"Service '{svc}' failed {len(evs)} times in {p['window_minutes']} minutes.")
            d.key = f"{self.id}|{svc}|"
            out.append(d)
        return out


class AccountLockouts(Rule):
    id = "HZ-006"
    name = "Account lockouts"
    description = "An account was locked out, which may indicate a password-guessing attempt."
    severity = Severity.high
    event_types = [EventType.account_lockout]
    default_params: dict = {}

    def evaluate(self, new_events, history):
        groups = defaultdict(list)
        for e in new_events:
            if e.event_type in self.event_types:
                groups[(e.source_ip, e.username)].append(e)
        return [self._detection(evs, ip=ip, user=user) for (ip, user), evs in groups.items()]
