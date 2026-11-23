from __future__ import annotations

import json
from typing import Iterator

from app.processors.parser import parse_json_record


def iter_records(text: str) -> Iterator[dict | None]:
    """Accept a JSON array or JSON Lines."""
    stripped = text.strip()
    if not stripped:
        return
    if stripped.startswith("["):
        try:
            data = json.loads(stripped)
        except ValueError:
            yield None
            return
        for item in data:
            yield parse_json_record(item)
        return
    for line in stripped.splitlines():
        if not line.strip():
            continue
        try:
            yield parse_json_record(json.loads(line))
        except ValueError:
            yield None
