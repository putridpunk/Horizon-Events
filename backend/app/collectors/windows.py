from __future__ import annotations

import csv
import io
import json
from typing import Iterator

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from app.processors.parser import parse_windows_record


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_events(text: str) -> Iterator[dict | None]:
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, DefusedXmlException):
        yield None
        return
    for ev in [e for e in root.iter() if _local(e.tag) == "Event"]:
        flat: dict = {}
        unnamed = 0
        for el in ev.iter():
            name = _local(el.tag)
            if name == "TimeCreated":
                flat["TimeCreated"] = el.get("SystemTime")
            elif name == "Provider" and el.get("Name"):
                flat["Provider"] = el.get("Name")
            elif name == "Data":
                if el.get("Name"):
                    flat[el.get("Name")] = (el.text or "").strip()
                else:  # some events (e.g. application crashes) have positional, unnamed values
                    flat[f"Data{unnamed}"] = (el.text or "").strip()
                    unnamed += 1
            elif name in ("EventID", "Computer", "EventRecordID", "Channel") and el.text:
                flat[name] = el.text.strip()
        yield parse_windows_record(flat)


def iter_windows(text: str) -> Iterator[dict | None]:
    s = text.strip()
    if not s:
        return
    if s.startswith("<"):
        yield from _xml_events(s)
    elif s.startswith("[") or s.startswith("{"):
        try:
            data = json.loads(s)
            items = data if isinstance(data, list) else [data]
        except ValueError:
            items = None
        if items is None:  # JSON Lines
            for line in s.splitlines():
                try:
                    yield parse_windows_record(json.loads(line))
                except ValueError:
                    yield None
        else:
            for item in items:
                yield parse_windows_record(item)
    else:
        try:
            for row in csv.DictReader(io.StringIO(s, newline="")):
                yield parse_windows_record(row)
        except csv.Error:
            yield None
