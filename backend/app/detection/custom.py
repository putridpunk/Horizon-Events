"""Rules the user writes. A rule is a tree of conditions over the normalised fields of an event, plus how many
matches in how many minutes it takes to raise an alert, and what to group the matches by. Pure Python like the
built-in rules: no web or database imports.

    {"when": {"all": [{"field": "event_type", "op": "eq", "value": "authentication_failure"},
                      {"field": "username", "op": "in", "value": ["root", "admin"]}]},
     "threshold": 5, "window_minutes": 10, "group_by": "source_ip"}

A node is `{"all": [...]}`, `{"any": [...]}`, `{"not": node}` or a condition `{"field", "op", "value"}`.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from collections import defaultdict
from datetime import timedelta

from app.detection.rules import Rule, _best_window
from app.domain import SEVERITY_RANK, Detection, Event, EventType, Severity

ID_PREFIX = "CR-"
MAX_DEPTH = 6
MAX_CONDITIONS = 30
MAX_VALUE_LENGTH = 500
MAX_THRESHOLD = 10_000
MAX_WINDOW_MINUTES = 7 * 24 * 60
GROUP_BY = ("none", "source_ip", "username", "host", "service")

FIELDS = ("event_type", "severity", "username", "source_ip", "host", "service", "source", "message", "raw")
OPS = ("eq", "ne", "contains", "not_contains", "startswith", "endswith", "in", "glob", "cidr", "severity_gte",
       "severity_lte", "present", "absent", "raw_field")
_NO_VALUE = {"present", "absent"}
_LIST_OPS = {"in"}
RAW_MODES = ("eq", "contains", "startswith", "endswith")
_FIELD_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")


class RuleError(ValueError):
    """A rule definition that cannot be accepted; the message is shown to the user."""


def _strings(value) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    return [p.strip() for p in str(value).split(",") if p.strip()]


def _validate_node(node, depth: int, counter: list[int]):
    if depth > MAX_DEPTH:
        raise RuleError(f"Conditions can be nested at most {MAX_DEPTH} levels deep.")
    if not isinstance(node, dict):
        raise RuleError("Each condition must be an object.")
    for key in ("all", "any"):
        if key in node:
            items = node[key]
            if set(node) != {key} or not isinstance(items, list) or not items:
                raise RuleError(f'"{key}" must be a non-empty list of conditions and nothing else.')
            return {key: [_validate_node(n, depth + 1, counter) for n in items]}
    if "not" in node:
        if set(node) != {"not"}:
            raise RuleError('"not" must stand alone.')
        return {"not": _validate_node(node["not"], depth + 1, counter)}
    counter[0] += 1
    if counter[0] > MAX_CONDITIONS:
        raise RuleError(f"A rule can have at most {MAX_CONDITIONS} conditions.")
    field, op, value = node.get("field"), node.get("op"), node.get("value")
    if field not in FIELDS:
        raise RuleError(f"Unknown field {field!r}. Fields: {', '.join(FIELDS)}.")
    if op not in OPS:
        raise RuleError(f"Unknown test {op!r}. Tests: {', '.join(OPS)}.")
    if op in _NO_VALUE:
        return {"field": field, "op": op}
    if op == "raw_field":
        name = node.get("name")
        if field != "raw" or not isinstance(name, str) or not _FIELD_NAME.match(name):
            raise RuleError('"raw_field" needs field "raw" and the name of a Windows event field, for example "EventID".')
    if value is None or (isinstance(value, str) and not value.strip()) or value == []:
        raise RuleError(f"The test {op!r} on {field} needs a value.")
    texts = _strings(value) if op in _LIST_OPS else [str(value)]
    if any(len(t) > MAX_VALUE_LENGTH for t in texts):
        raise RuleError(f"A value can have at most {MAX_VALUE_LENGTH} characters.")
    if op in ("severity_gte", "severity_lte"):
        if field != "severity" or str(value).lower() not in {s.value for s in Severity}:
            raise RuleError("Severity tests need the field severity and one of low, medium, high, critical.")
    if op == "cidr":
        if field != "source_ip":
            raise RuleError("The cidr test works on source_ip.")
        for t in texts:
            try:
                ipaddress.ip_network(t, strict=False)
            except ValueError:
                raise RuleError(f"{t!r} is not an address or address block.") from None
    if field == "event_type" and op in ("eq", "ne", "in"):
        known = {t.value for t in EventType}
        bad = [t for t in texts if t.lower() not in known]
        if bad:
            raise RuleError(f"{bad[0]!r} is not an event type. Types: {', '.join(sorted(known))}.")
    if field == "severity" and op in ("eq", "ne", "in"):
        known = {s.value for s in Severity}
        bad = [t for t in texts if t.lower() not in known]
        if bad:
            raise RuleError(f"{bad[0]!r} is not a severity (low, medium, high, critical).")
    clean = {"field": field, "op": op, "value": texts if op in _LIST_OPS else str(value)}
    if op == "raw_field":
        clean["name"] = node["name"]
        clean["mode"] = node.get("mode", "eq")
        if clean["mode"] not in RAW_MODES:
            raise RuleError(f"A raw_field mode must be one of: {', '.join(RAW_MODES)}.")
    return clean


def validate_params(params: dict | None) -> dict:
    """Return the cleaned parameters of a custom rule, or raise RuleError saying what is wrong."""
    params = params or {}
    if "when" not in params:
        raise RuleError("A rule needs conditions: add at least one.")
    when = _validate_node(params["when"], 1, [0])
    try:
        threshold = int(params.get("threshold", 1))
        window = int(params.get("window_minutes", 10))
    except (TypeError, ValueError):
        raise RuleError("The count and the number of minutes must be whole numbers.") from None
    if not 1 <= threshold <= MAX_THRESHOLD:
        raise RuleError(f"The count must be between 1 and {MAX_THRESHOLD}.")
    if not 1 <= window <= MAX_WINDOW_MINUTES:
        raise RuleError(f"The time window must be between 1 minute and {MAX_WINDOW_MINUTES} minutes (one week).")
    group_by = params.get("group_by", "none")
    if group_by not in GROUP_BY:
        raise RuleError(f"Group by must be one of: {', '.join(GROUP_BY)}.")
    return {"when": when, "threshold": threshold, "window_minutes": window, "group_by": group_by}


# ---- evaluation ------------------------------------------------------------------------------------------------
def _value(event: Event, field: str) -> str:
    if field in ("event_type", "severity"):
        return getattr(event, field).value
    return str(getattr(event, field, None) or "")


def _test(event: Event, cond: dict) -> bool:
    field, op = cond["field"], cond["op"]
    actual = _value(event, field)
    low = actual.lower()
    if op == "present":
        return bool(actual)
    if op == "absent":
        return not actual
    value = cond["value"]
    if op == "in":
        return low in {v.lower() for v in value}
    value_low = str(value).lower()
    if op == "eq":
        return low == value_low
    if op == "ne":
        return low != value_low
    if op == "contains":
        return value_low in low
    if op == "not_contains":
        return value_low not in low
    if op == "startswith":
        return low.startswith(value_low)
    if op == "endswith":
        return low.endswith(value_low)
    if op == "glob":
        return fnmatch.fnmatchcase(low, value_low)
    if op == "cidr":
        try:
            return bool(actual) and ipaddress.ip_address(actual) in ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False
    if op in ("severity_gte", "severity_lte"):
        rank, wanted = SEVERITY_RANK[event.severity], SEVERITY_RANK[Severity(value_low)]
        return rank >= wanted if op == "severity_gte" else rank <= wanted
    if op == "raw_field":  # Windows events keep their fields in the raw text as "Name=value Name2=value2"
        pattern = rf"(?:^| ){re.escape(cond['name'])}=(.*?)(?= \S+=|$)"
        found = re.search(pattern, event.raw)
        if not found:
            return False
        got, mode = found[1].strip().lower(), cond.get("mode", "eq")
        return {"eq": got == value_low, "contains": value_low in got, "startswith": got.startswith(value_low),
                "endswith": got.endswith(value_low)}[mode]
    return False


def matches(node: dict, event: Event) -> bool:
    if "all" in node:
        return all(matches(n, event) for n in node["all"])
    if "any" in node:
        return any(matches(n, event) for n in node["any"])
    if "not" in node:
        return not matches(node["not"], event)
    return _test(event, node)


def _type_hint(node: dict) -> list[EventType]:
    """Event types the rule can only match, so that history is read for those alone (all types if unknown)."""
    if "all" in node:
        hints = [h for h in (_type_hint(n) for n in node["all"]) if h]
        return min(hints, key=len) if hints else []
    if "field" in node and node["field"] == "event_type" and node["op"] in ("eq", "in"):
        values = node["value"] if node["op"] == "in" else [node["value"]]
        return [EventType(v.lower()) for v in values]
    return []


class CustomRule(Rule):
    default_params = {"threshold": 1, "window_minutes": 10, "group_by": "none"}

    def __init__(self, rule_id: str, name: str, description: str, severity, params: dict | None):
        super().__init__(severity=severity, params=params)
        self.id, self.name, self.description = rule_id, name, description
        self.event_types = _type_hint(self.params["when"]) or list(EventType)

    def _group_value(self, event: Event) -> str | None:
        group_by = self.params["group_by"]
        return "" if group_by == "none" else (_value(event, group_by) or None)

    def evaluate(self, new_events, history) -> list[Detection]:
        tree, threshold = self.params["when"], self.params["threshold"]
        group_by, window = self.params["group_by"], timedelta(minutes=self.params["window_minutes"])
        groups: dict[str, list[Event]] = defaultdict(list)
        for e in new_events:
            if matches(tree, e):
                value = self._group_value(e)
                if value is not None:
                    groups[value].append(e)
        out: list[Detection] = []
        for value, events in groups.items():
            chosen = events
            if threshold > 1:
                lo, hi = min(e.timestamp for e in events) - window, max(e.timestamp for e in events)
                scope = {group_by: value} if group_by in ("source_ip", "username", "service") and value else {}
                seen = history.events_in_window(self.event_types, lo, hi, **scope)
                seen = [e for e in seen if matches(tree, e) and (group_by in ("none", "source_ip", "username", "service")
                                                                 or _value(e, group_by) == value)]
                chosen = _best_window(seen, {e.id for e in events}, window)
                if len(chosen) < threshold:
                    continue
            ip = next((e.source_ip for e in chosen if e.source_ip), None) if group_by in ("none", "source_ip") else None
            user = next((e.username for e in chosen if e.username), None) if group_by in ("none", "username") else None
            if group_by == "source_ip":
                ip = value
            if group_by == "username":
                user = value
            noun = "event" if len(chosen) == 1 else "events"
            span = f" within {self.params['window_minutes']} minutes" if threshold > 1 else ""
            detection = self._detection(
                chosen, ip=ip, user=user, window=self.params["window_minutes"] if threshold > 1 else None,
                description=f"{self.description.rstrip('. ')} ({len(chosen)} matching {noun}{span}).")
            detection.key = f"{self.id}|{group_by}:{value}|"
            out.append(detection)
        return out
