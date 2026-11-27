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


class ExplicitCredentialLogon(Rule):
    id = "HZ-013"
    name = "Logon with explicit credentials"
    description = "A program signed in with another account's password (event 4648). Attackers do this to move sideways."
    severity = Severity.medium
    event_types = [EventType.explicit_credentials]
    default_params = {"threshold": 3, "window_minutes": 10}

    def evaluate(self, new_events, history):
        out = []
        for user, evs in self._windowed_groups(new_events, history, lambda e: e.username or "",
                                               self.params["window_minutes"], self.params["threshold"]):
            out.append(self._detection(evs, user=user or None, window=self.params["window_minutes"]))
        return out

    def _scope(self, group_key):
        return {"username": group_key or None}


class NtlmNetworkLogon(Rule):
    id = "HZ-014"
    name = "NTLM network logon"
    description = "A sign-in over the network used NTLM, the protocol that pass-the-hash attacks rely on."
    severity = Severity.medium
    event_types = [EventType.ntlm_logon]
    default_params = {"ignore_private": True}

    def evaluate(self, new_events, history):
        groups = defaultdict(list)
        for e in new_events:
            if e.event_type not in self.event_types or not e.username:
                continue
            if e.username.endswith("$") or e.username.upper() in ("ANONYMOUS LOGON", "-"):
                continue  # machine accounts and anonymous sessions are routine
            if self.params["ignore_private"] and not RemoteDesktopLogin._public(e.source_ip):
                continue
            groups[(e.source_ip, e.username)].append(e)
        return [self._detection(evs, ip=ip, user=user, severity=Severity.high) for (ip, user), evs in groups.items()]


class NewLocalAdministrator(Rule):
    id = "HZ-015"
    name = "New local administrator"
    description = "An account was added to the Administrators group. Check that you expected it."
    severity = Severity.high
    event_types = [EventType.privilege_escalation]
    default_params = {"groups": ["administrators", "administradores", "administrateurs", "administratoren",
                                 "domain admins", "enterprise admins"]}

    def evaluate(self, new_events, history):
        wanted = {g.lower() for g in self.params["groups"]}
        groups = defaultdict(list)
        for e in new_events:
            group = (e.metadata or {}).get("group", "")
            if e.event_type in self.event_types and group.lower() in wanted:
                groups[(e.username, group.lower())].append(e)
        return [self._detection(evs, user=user,
                                severity=Severity.critical if grp.startswith(("domain", "enterprise")) else None)
                for (user, grp), evs in groups.items()]


class SuspiciousPowerShell(Rule):
    id = "HZ-016"
    name = "Suspicious PowerShell"
    description = "A PowerShell script contained a pattern often used by attackers, such as encoded or downloaded code."
    severity = Severity.high
    event_types = [EventType.powershell_script]
    default_params = {"keywords": ["-encodedcommand", "frombase64string", "invoke-expression", "iex(", "iex (",
                                   "downloadstring", "downloadfile", "invoke-mimikatz", "amsiutils",
                                   "-executionpolicy bypass", "-windowstyle hidden", "net.webclient"]}

    def evaluate(self, new_events, history):
        keys = [k.lower() for k in self.params["keywords"] if k]
        groups = defaultdict(list)
        for e in new_events:
            if e.event_type not in self.event_types:
                continue
            script = ((e.metadata or {}).get("script") or e.message).lower()
            hit = next((k for k in keys if k in script), None)
            if hit:
                groups[hit].append(e)
        return [self._detection(evs, description=f"A PowerShell script contained '{hit}', "
                                                  "a pattern often used by attackers.")
                for hit, evs in groups.items()]


class UsbDevice(Rule):
    id = "HZ-017"
    name = "External device connected"
    description = "A new external device (such as a USB drive) was recognised by Windows."
    severity = Severity.low
    event_types = [EventType.usb_device]
    default_params = {"ignore": []}

    def evaluate(self, new_events, history):
        groups = defaultdict(list)
        for e in new_events:
            device = (e.metadata or {}).get("device", "")
            if e.event_type in self.event_types and not any(
                    device.lower().startswith(p.lower()) for p in self.params["ignore"] if p):
                groups[device].append(e)
        out = []
        for device, evs in groups.items():
            d = self._detection(evs, description=f"An external device was connected: {device}." if device else None)
            d.key = f"{self.id}|{device}|"
            out.append(d)
        return out
