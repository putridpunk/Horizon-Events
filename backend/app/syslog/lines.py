"""Turn network syslog messages (RFC 3164 and RFC 5424), journald entries and macOS log entries into the classic
`Mon dd hh:mm:ss host program[pid]: message` line the Linux parsers already understand, and decide which parser
should read each line. Pure functions: no sockets, no database."""
from __future__ import annotations

import re
from datetime import datetime, timezone

MAX_LINE = 8192
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

# Programs that report who signed in or gained privileges: read by the authentication parser.
AUTH_PROGRAMS = frozenset({"sshd", "sudo", "su", "login", "passwd", "systemd-logind", "polkitd", "gdm", "gdm-password",
                           "lightdm", "doas", "pam_unix", "unix_chkpwd", "cron", "loginwindow", "authd", "opendirectoryd",
                           "securityd", "screensharingd"})

_PRI = re.compile(r"^<(\d{1,3})>")
_RFC5424 = re.compile(r"^1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<pid>\S+) (?P<msgid>\S+) "
                      r"(?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+) ?(?P<msg>.*)$", re.S)
_RFC3164 = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+(?P<rest>.*)$", re.S)
_TAG = re.compile(r"^(?P<prog>[^\s:\[\]]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$", re.S)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def clean(text: str, limit: int = MAX_LINE) -> str:
    """One line, no control characters (so a message cannot forge another log line)."""
    return " ".join(_CONTROL.sub(" ", text.replace("\r", " ").replace("\n", " ")).split())[:limit]


def format_line(when: datetime, host: str, program: str, pid: str | int | None, message: str) -> str:
    """`when` is naive UTC. The program and host are made safe for the parsers (no spaces, colons or brackets)."""
    safe = lambda s, default: re.sub(r"[\s:\[\]]", "_", s or "") or default  # noqa: E731
    tag = safe(program, "unknown") + (f"[{pid}]" if pid not in (None, "", "-") and str(pid).isdigit() else "")
    return f"{MONTHS[when.month - 1]} {when.day:2d} {when:%H:%M:%S} {safe(host, 'unknown')} {tag}: {clean(message)}"


def _utc(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value


def parse_datagram(data: bytes | str, received: datetime, sender: str | None = None) -> str | None:
    """One syslog message to one normalised line, or None for an empty message.

    A message without a timestamp or host (some devices send only the text) gets the time it arrived and the
    address it came from."""
    text = data if isinstance(data, str) else data.decode("utf-8", errors="replace")
    text = text.strip("\x00\r\n ")[:MAX_LINE * 2]
    if not text:
        return None
    text = _PRI.sub("", text, count=1)
    m = _RFC5424.match(text)
    if m:
        try:
            when = _utc(datetime.fromisoformat(m["ts"].replace("Z", "+00:00")))
        except ValueError:
            when = received
        host = m["host"] if m["host"] != "-" else (sender or "unknown")
        app = m["app"] if m["app"] != "-" else "unknown"
        return format_line(when, host, app, m["pid"], m["msg"].removeprefix("\ufeff"))
    m = _RFC3164.match(text)
    if m:
        rest = _TAG.match(m["rest"])
        if rest:
            when = _syslog_time(m["ts"], received)
            return format_line(when, m["host"], rest["prog"], rest["pid"], rest["msg"])
        return format_line(_syslog_time(m["ts"], received), m["host"], "unknown", None, m["rest"])
    tagged = _TAG.match(text)  # "sshd[12]: text" with no header
    if tagged:
        return format_line(received, sender or "unknown", tagged["prog"], tagged["pid"], tagged["msg"])
    return format_line(received, sender or "unknown", "unknown", None, text)


def _syslog_time(text: str, received: datetime) -> datetime:
    mon, day, hms = text.split()
    try:
        when = datetime.strptime(f"{received.year} {MONTHS.index(mon) + 1} {int(day)} {hms}", "%Y %m %d %H:%M:%S")
    except ValueError:
        return received
    if (when - received).days >= 1:  # a December message arriving in January
        when = when.replace(year=when.year - 1)
    return when


def program_of(line: str) -> str:
    m = re.match(r"^\S+\s+\d+\s+\S+\s+\S+\s+([^\s:\[]+)", line)
    return m[1].lower() if m else ""


def source_type_for(line: str) -> str:
    return "linux_auth" if program_of(line) in AUTH_PROGRAMS else "linux_syslog"


def route(lines: list[str]) -> dict[str, bytes]:
    """Group lines by the parser that should read them."""
    out: dict[str, list[str]] = {}
    for line in lines:
        out.setdefault(source_type_for(line), []).append(line)
    return {k: ("\n".join(v) + "\n").encode("utf-8") for k, v in out.items()}
