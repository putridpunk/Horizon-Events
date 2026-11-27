"""Builders for Windows Event Log XML shaped like `wevtutil qe <channel> /f:xml` output.

Real output has single-quoted attributes, a namespaced <Event>, seven fractional digits in SystemTime,
and (for some events) <Data> elements without a Name. The data here is synthetic.
"""
from __future__ import annotations

from xml.sax.saxutils import escape, quoteattr

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
PROVIDERS = {"Security": "Microsoft-Windows-Security-Auditing", "System": "Service Control Manager",
             "Application": "Application Error"}


def event_xml(channel: str, event_id: int, record_id: int, when: str = "2026-11-23T14:20:31",
              data: dict | None = None, unnamed: list[str] | None = None, computer: str = "WS-DEMO") -> str:
    named = "".join(f"<Data Name={quoteattr(k)}>{escape(str(v))}</Data>" for k, v in (data or {}).items())
    plain = "".join(f"<Data>{escape(v)}</Data>" for v in (unnamed or []))
    return (
        f"<Event xmlns='{NS}'><System><Provider Name={quoteattr(PROVIDERS.get(channel, 'Provider'))}/>"
        f"<EventID>{event_id}</EventID><Version>0</Version><Level>0</Level><Task>0</Task><Opcode>0</Opcode>"
        f"<Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='{when}.1234567Z'/>"
        f"<EventRecordID>{record_id}</EventRecordID><Correlation/><Execution ProcessID='652' ThreadID='1234'/>"
        f"<Channel>{channel}</Channel><Computer>{computer}</Computer><Security/></System>"
        f"<EventData>{named}{plain}</EventData></Event>")


def logon_failure(record_id: int, user: str = "admin", ip: str = "203.0.113.7", when="2026-11-23T14:20:31",
                  sub_status: str = "0xc000006a") -> str:
    return event_xml("Security", 4625, record_id, when, {
        "SubjectUserName": "WS-DEMO$", "TargetUserName": user, "Status": "0xc000006d",
        "SubStatus": sub_status, "LogonType": "3", "IpAddress": ip, "IpPort": "49152"})


def logon_success(record_id: int, user: str = "alice", logon_type: int = 2, ip: str = "-",
                  when="2026-11-23T09:05:00") -> str:
    return event_xml("Security", 4624, record_id, when, {
        "SubjectUserName": "WS-DEMO$", "TargetUserName": user, "LogonType": str(logon_type), "IpAddress": ip})


def lockout(record_id: int, user: str = "bob", when="2026-11-23T11:10:30") -> str:
    return event_xml("Security", 4740, record_id, when, {
        "SubjectUserName": "WS-DEMO$", "TargetUserName": user, "TargetDomainName": "WS-DEMO"})


def group_change(record_id: int, event_id: int = 4732, who: str = "carol", group: str = "Administrators",
                 member: str = "tmp_contractor", when="2026-11-23T13:41:00") -> str:
    return event_xml("Security", event_id, record_id, when, {
        "MemberName": member, "TargetUserName": group, "SubjectUserName": who})


def service_crash(record_id: int, service: str = "Spooler", event_id: int = 7031, when="2026-11-23T13:50:00") -> str:
    return event_xml("System", event_id, record_id, when, {"param1": service, "param2": "1"})


def app_crash(record_id: int, app: str = "chrome.exe", when="2026-11-23T15:00:00") -> str:
    return event_xml("Application", 1000, record_id, when, unnamed=[app, "120.0.0.0", "654a1b2c"])


def wrap(*events: str) -> str:
    """What the collector does with `wevtutil` output: give the concatenated events a root."""
    return "<Events>" + "".join(events) + "</Events>"


def log_cleared(record_id: int, who: str = "mallory", event_id: int = 1102, when="2026-11-23T03:12:00") -> str:
    return event_xml("Security" if event_id == 1102 else "System", event_id, record_id, when, {
        "SubjectUserName": who, "SubjectDomainName": "WS-DEMO"})


def service_installed(record_id: int, name: str = "EvilSvc", event_id: int = 7045, image: str = r"C:\Temp\evil.exe",
                      when="2026-11-23T03:15:00") -> str:
    return event_xml("System" if event_id == 7045 else "Security", event_id, record_id, when, {
        "ServiceName": name, "ImagePath": image, "ServiceType": "user mode service", "StartType": "auto start",
        "SubjectUserName": "mallory"})


def task_created(record_id: int, name: str = r"\Updater", who: str = "mallory", when="2026-11-23T03:20:00") -> str:
    return event_xml("Security", 4698, record_id, when, {"SubjectUserName": who, "TaskName": name})


def ntlm_logon(record_id: int, user: str = "svc_backup", ip: str = "93.184.216.34", when="2026-11-23T04:00:00") -> str:
    return event_xml("Security", 4624, record_id, when, {
        "SubjectUserName": "-", "TargetUserName": user, "LogonType": "3", "IpAddress": ip,
        "AuthenticationPackageName": "NTLM"})


def explicit_logon(record_id: int, who: str = "alice", target: str = "admin", when="2026-11-23T10:00:00") -> str:
    return event_xml("Security", 4648, record_id, when, {"SubjectUserName": who, "TargetUserName": target})


def powershell_block(record_id: int, script: str = "Get-Date", when="2026-11-23T10:30:00") -> str:
    return event_xml("Microsoft-Windows-PowerShell/Operational", 4104, record_id, when, {"ScriptBlockText": script})


def usb_device(record_id: int, device: str = "USB Mass Storage Device", when="2026-11-23T10:45:00") -> str:
    return event_xml("Security", 6416, record_id, when, {"DeviceDescription": device, "SubjectUserName": "alice"})
