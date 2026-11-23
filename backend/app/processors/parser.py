"""Format-specific parsers. Each returns an intermediate dict or None if unparseable."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

_SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[\d+\])?:\s*(?P<msg>.*)$")

_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
_FAILED_INVALID = re.compile(rf"Failed \w+ for invalid user (?P<user>\S+) from {_IP}")
_INVALID_USER = re.compile(rf"Invalid user (?P<user>\S+) from {_IP}")
_FAILED = re.compile(rf"Failed \w+ for (?P<user>\S+) from {_IP}")
_ACCEPTED = re.compile(rf"Accepted \w+ for (?P<user>\S+) from {_IP}")
_SUDO = re.compile(r"^(?P<user>\S+)\s+:\s+.*USER=root\s*;\s*COMMAND=")
_SU = re.compile(r"session opened for user root by (?P<user>\w+)")
_LOCK = re.compile(r"user (?P<user>\S+) \(locked\)|account (?:for )?(?P<user2>\S+) locked|locked out", re.I)
_UNIT_FAIL = re.compile(r"^(?P<svc>[\w@.\-]+?)(?:\.service)?: (?:Failed with result|Main process exited.*status=[1-9]|Failed)")
_UNIT_FAIL2 = re.compile(r"Failed to start (?P<svc>[\w@.\-]+?)(?:\.service)?\b")
_UNIT_START = re.compile(r"^Started (?P<svc>.+?)\.?$")


def _syslog_time(mon: str, day: str, hms: str, now: datetime) -> datetime | None:
    if mon not in _MONTHS:
        return None
    try:
        ts = datetime.strptime(f"{now.year} {_MONTHS[mon]} {int(day)} {hms}", "%Y %m %d %H:%M:%S")
    except ValueError:
        return None
    if ts - now > timedelta(days=1):
        ts = ts.replace(year=ts.year - 1)
    return ts


def _header(line: str, now: datetime) -> dict | None:
    m = _SYSLOG.match(line.strip())
    if not m:
        return None
    ts = _syslog_time(m["mon"], m["day"], m["time"], now)
    if ts is None:
        return None
    return {"timestamp": ts, "host": m["host"], "process": m["proc"], "message": m["msg"], "raw": line.strip()}


def parse_linux_auth(line: str, now: datetime) -> dict | None:
    base = _header(line, now)
    if base is None:
        return None
    msg = base["message"]
    for pattern, hint in ((_FAILED_INVALID, "unknown_user"), (_INVALID_USER, "unknown_user"),
                          (_FAILED, "authentication_failure"), (_ACCEPTED, "authentication_success")):
        m = pattern.search(msg)
        if m:
            base.update(event_hint=hint, username=m["user"], source_ip=m["ip"])
            return base
    m = _SUDO.match(msg) or _SU.search(msg)
    if m:
        base.update(event_hint="privilege_escalation", username=m["user"])
        return base
    m = _LOCK.search(msg)
    if m:
        base.update(event_hint="account_lockout", username=m.group("user") or m.group("user2"))
        return base
    base["event_hint"] = "generic"
    return base


def parse_syslog(line: str, now: datetime) -> dict | None:
    base = _header(line, now)
    if base is None:
        return None
    msg = base["message"]
    m = _UNIT_FAIL.match(msg) or _UNIT_FAIL2.search(msg)
    if m:
        base.update(event_hint="service_failure", service=m["svc"])
        return base
    m = _UNIT_START.match(msg)
    if m and base["process"] == "systemd":
        base.update(event_hint="service_start", service=m["svc"])
        return base
    base["event_hint"] = "generic"
    return base


def _parse_iso(value) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


_WIN_MAP = {
    "4624": "authentication_success", "4625": "authentication_failure", "4740": "account_lockout",
    "4672": "privilege_escalation", "4728": "privilege_escalation", "4732": "privilege_escalation",
    "4756": "privilege_escalation", "7031": "service_failure", "7034": "service_failure",
    "1000": "service_failure",
}

# Short, language-independent descriptions for the events the live collector reads.
_WIN_TEXT = {
    "4624": "Successful logon", "4625": "Failed logon", "4740": "Account locked out",
    "4720": "User account created", "4728": "Member added to a global security group",
    "4732": "Member added to a local security group", "4756": "Member added to a universal security group",
    "7031": "Service terminated unexpectedly", "7034": "Service terminated unexpectedly",
    "1000": "Application crashed",
}
# For these events TargetUserName is the group; the account of interest is who made the change.
_SUBJECT_FIRST = {"4728", "4732", "4756"}


def parse_windows_record(rec: dict) -> dict | None:
    if not isinstance(rec, dict):
        return None
    r = {str(k).lower(): v for k, v in rec.items()}
    eid = str(r.get("eventid", "")).strip()
    ts = _parse_iso(r.get("timecreated") or r.get("timestamp") or "")
    if not eid or ts is None:
        return None
    hint = _WIN_MAP.get(eid, "generic")
    if eid in _SUBJECT_FIRST:
        user = r.get("subjectusername") or r.get("targetusername") or None
    else:
        user = r.get("targetusername") or r.get("subjectusername") or r.get("username") or None
    if user in ("-", ""):
        user = None
    ip = r.get("ipaddress") or r.get("sourceip") or None
    if ip in ("-", "::1", ""):
        ip = None
    if eid == "4625" and str(r.get("substatus", "")).lower() == "0xc0000064":
        hint = "unknown_user"
    out = {
        "timestamp": ts, "host": r.get("computer"), "process": "windows", "event_hint": hint,
        "message": str(r.get("message") or (f"{_WIN_TEXT[eid]} ({eid})" if eid in _WIN_TEXT else f"Windows event {eid}")),
        "raw": " ".join(f"{k}={v}" for k, v in rec.items()),
        "username": user, "source_ip": ip,
    }
    if hint == "service_failure":
        out["service"] = r.get("servicename") or r.get("param1") or r.get("data0")
    return out


_APP = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d)\S*\s+(?P<lvl>DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL)\s+"
    r"(?:\[(?P<svc>[^\]]+)\]\s+)?(?P<msg>.*)$")
_APP_USER = re.compile(r"user[= ](?P<u>\w+)", re.I)
_APP_IP = re.compile(r"(?:ip[= ]|from )(?P<ip>\d{1,3}(?:\.\d{1,3}){3})", re.I)


def parse_app_line(line: str) -> dict | None:
    m = _APP.match(line.strip())
    if not m:
        return None
    ts = _parse_iso(m["ts"].replace(" ", "T"))
    if ts is None:
        return None
    lvl, msg = m["lvl"], m["msg"]
    hint = "generic"
    if re.search(r"login failed|authentication failed", msg, re.I):
        hint = "authentication_failure"
    elif lvl in ("ERROR", "CRITICAL", "FATAL"):
        hint = "service_failure"
    u, ip = _APP_USER.search(msg), _APP_IP.search(msg)
    return {
        "timestamp": ts, "host": None, "process": m["svc"] or "app", "message": msg, "raw": line.strip(),
        "event_hint": hint, "service": m["svc"], "username": u["u"] if u else None,
        "source_ip": ip["ip"] if ip else None, "level": lvl,
    }


def parse_json_record(rec: dict) -> dict | None:
    if not isinstance(rec, dict):
        return None
    ts = _parse_iso(rec.get("timestamp"))
    if ts is None:
        return None
    return {
        "timestamp": ts, "host": rec.get("host"), "process": rec.get("service") or "json",
        "message": str(rec.get("message", "")), "raw": str(rec),
        "event_hint": rec.get("event_type", "generic"), "severity": rec.get("severity"),
        "username": rec.get("username"), "source_ip": rec.get("source_ip"), "service": rec.get("service"),
    }
