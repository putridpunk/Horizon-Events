from __future__ import annotations

from datetime import datetime
from typing import Iterator

from app.processors.parser import parse_linux_auth, parse_syslog


def iter_auth(text: str, now: datetime) -> Iterator[dict | None]:
    for line in text.splitlines():
        if line.strip():
            yield parse_linux_auth(line, now)


def iter_syslog(text: str, now: datetime) -> Iterator[dict | None]:
    for line in text.splitlines():
        if line.strip():
            yield parse_syslog(line, now)
