"""Collection entry point: bytes + source type -> normalised events."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.collectors import application, json_collector, linux, windows
from app.domain import Event
from app.processors.normalizer import normalize

SOURCE_TYPES = ("linux_auth", "linux_syslog", "windows", "application", "json")


@dataclass
class ImportResult:
    total: int
    imported: int
    skipped: int


def collect(source_type: str, content: bytes, now: datetime | None = None) -> tuple[list[Event], ImportResult]:
    if source_type not in SOURCE_TYPES:
        raise ValueError(f"Unknown source type: {source_type}")
    now = now or datetime.now()
    text = content.decode("utf-8", errors="replace").replace("\x00", "")
    if source_type == "linux_auth":
        it = linux.iter_auth(text, now)
    elif source_type == "linux_syslog":
        it = linux.iter_syslog(text, now)
    elif source_type == "windows":
        it = windows.iter_windows(text)
    elif source_type == "application":
        it = application.iter_app(text)
    else:
        it = json_collector.iter_records(text)
    events: list[Event] = []
    total = skipped = 0
    for parsed in it:
        total += 1
        if parsed is None:
            skipped += 1
            continue
        try:
            events.append(normalize(parsed, source_type))
        except (KeyError, TypeError, ValueError):
            skipped += 1
    return events, ImportResult(total=total, imported=len(events), skipped=skipped)
