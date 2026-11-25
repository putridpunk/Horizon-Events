"""Rules for Windows events that signal persistence, defence evasion or remote access. Pure Python, like rules.py."""
from __future__ import annotations

import ipaddress
from collections import defaultdict

from app.detection.rules import Rule
from app.domain import Detection, EventType, Severity


class AuditLogCleared(Rule):
    id = "HZ-009"
    name = "Audit log cleared"
    description = "A Windows event log was cleared. Attackers do this to remove the evidence of what they did."
    severity = Severity.critical
    event_types = [EventType.log_cleared]
    default_params: dict = {}

    def evaluate(self, new_events, history):
        groups = defaultdict(list)
        for e in new_events:
            if e.event_type in self.event_types:
                groups[e.username].append(e)
        return [self._detection(evs, user=user) for user, evs in groups.items()]


class _ByName(Rule):
    """One detection per service or task name (the name goes into the alert key, so different names stay separate)."""
    noun = "item"
    default_params: dict = {"ignore": []}

    def _ignored(self, name: str) -> bool:
        return any(name.lower().startswith(p.lower()) for p in self.params["ignore"] if p)

    def evaluate(self, new_events, history):
        groups = defaultdict(list)
        for e in new_events:
            if e.event_type in self.event_types and not (e.service and self._ignored(e.service)):
                groups[e.service or ""].append(e)
        out: list[Detection] = []
        for name, evs in groups.items():
            who = next((e.username for e in evs if e.username), None)
            d = self._detection(evs, user=who, description=(
                f"A new {self.noun} was created: {name}." if name else f"A new {self.noun} was created."))
            d.key = f"{self.id}|{name}|"
            out.append(d)
        return out


class ServiceInstalled(_ByName):
    id = "HZ-010"
    name = "New service installed"
    description = "A new Windows service was installed. Attackers use services to run code at every start-up."
    severity = Severity.medium
    event_types = [EventType.service_installed]
    noun = "service"
    default_params = {"ignore": []}


class ScheduledTaskCreated(_ByName):
    id = "HZ-011"
    name = "Scheduled task created"
    description = "A scheduled task was created. Attackers use tasks to run code later or to stay on a machine."
    severity = Severity.medium
    event_types = [EventType.scheduled_task_created]
    noun = "scheduled task"
    default_params = {"ignore": ["\\Microsoft\\"]}  # Windows creates many of its own tasks


class RemoteDesktopLogin(Rule):
    id = "HZ-012"
    name = "Remote desktop logon"
    description = "Someone signed in through Remote Desktop. Check that it was you, or someone you expected."
    severity = Severity.medium
    event_types = [EventType.remote_login]
    default_params: dict = {}

    @staticmethod
    def _public(ip: str | None) -> bool:
        try:
            return bool(ip) and ipaddress.ip_address(ip).is_global
        except ValueError:
            return False

    def evaluate(self, new_events, history):
        groups = defaultdict(list)
        for e in new_events:
            if e.event_type in self.event_types:
                groups[(e.source_ip, e.username)].append(e)
        return [self._detection(evs, ip=ip, user=user, severity=Severity.high if self._public(ip) else None)
                for (ip, user), evs in groups.items()]
