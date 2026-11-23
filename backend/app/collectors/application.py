from __future__ import annotations

from typing import Iterator

from app.processors.parser import parse_app_line


def iter_app(text: str) -> Iterator[dict | None]:
    for line in text.splitlines():
        if line.strip():
            yield parse_app_line(line)
