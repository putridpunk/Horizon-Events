"""Turn a Sigma rule (the common YAML format for sharing detections) into a custom rule.

Only what Horizon Events can evaluate is accepted. Anything else is refused with a reason, because a rule that
silently matches the wrong things is worse than no rule:

* searches over fields, with the modifiers contains, startswith, endswith, all and cidr;
* keyword searches (a list of words);
* conditions made of search names, `and`, `or`, `not`, parentheses, and `1 of X*` / `all of X*` / `1 of them` /
  `all of them`.

Not supported: regular expressions (`|re`), encodings (`|base64`, `|windash` ...), aggregation (`| count`), `near`,
and field names Windows events do not carry. Fields that Horizon Events normalises (user, address, host, service,
message) are matched on those; other Windows field names are matched against the event's original fields.
"""
from __future__ import annotations

import fnmatch
import re

import yaml

from app.detection.custom import RuleError, validate_params

MAX_BYTES = 100_000
LEVELS = {"informational": "low", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}
FIELD_MAP = {
    "username": "username", "user": "username", "targetusername": "username", "accountname": "username",
    "subjectusername": "username", "samaccountname": "username",
    "ipaddress": "source_ip", "sourceip": "source_ip", "src_ip": "source_ip", "sourceaddress": "source_ip",
    "clientip": "source_ip", "sourcenetworkaddress": "source_ip",
    "computer": "host", "computername": "host", "hostname": "host", "host": "host",
    "servicename": "service", "service": "service", "message": "message",
}
SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "cidr"}


class SigmaError(ValueError):
    """A Sigma rule that cannot be imported; the message says why."""


def _leaf(field: str, mode: str, value) -> dict:
    mapped = FIELD_MAP.get(field.lower())
    if value is None:
        return {"field": mapped or "raw", "op": "absent"} if mapped else {"field": "raw", "op": "not_contains", "value": f"{field}="}
    value = str(value)
    if field.lower() == "eventid":
        return {"field": "raw", "op": "raw_field", "name": "EventID", "mode": "eq", "value": value}
    if mode == "cidr":
        if mapped != "source_ip":
            raise SigmaError("The cidr modifier works on address fields only.")
        return {"field": "source_ip", "op": "cidr", "value": value}
    if "*" in value or "?" in value:  # Sigma wildcards
        if mode == "eq":
            glob = value
        else:
            glob = {"contains": f"*{value}*", "startswith": f"{value}*", "endswith": f"*{value}"}[mode]
        if mapped:
            return {"field": mapped, "op": "glob", "value": glob}
        raise SigmaError(f"Wildcards in the value of {field} are only supported for fields Horizon Events normalises.")
    if mapped:
        return {"field": mapped, "op": {"eq": "eq", "contains": "contains", "startswith": "startswith",
                                        "endswith": "endswith"}[mode], "value": value}
    return {"field": "raw", "op": "raw_field", "name": field, "mode": mode, "value": value}


def _combine(kind: str, items: list[dict]) -> dict:
    return items[0] if len(items) == 1 else {kind: items}


def _field_search(key: str, value) -> dict:
    field, *mods = key.split("|")
    unsupported = [m for m in mods if m not in SUPPORTED_MODIFIERS]
    if unsupported:
        raise SigmaError(f"The modifier '|{unsupported[0]}' is not supported. Supported: "
                         f"{', '.join('|' + m for m in sorted(SUPPORTED_MODIFIERS))}.")
    mode = next((m for m in mods if m in ("contains", "startswith", "endswith", "cidr")), "eq")
    values = value if isinstance(value, list) else [value]
    if not values:
        raise SigmaError(f"The field '{field}' has no values.")
    leaves = [_leaf(field, mode, v) for v in values]
    return _combine("all" if "all" in mods else "any", leaves)


def _search(body) -> dict:
    if isinstance(body, dict):
        if not body:
            raise SigmaError("A search is empty.")
        return _combine("all", [_field_search(k, v) for k, v in body.items()])
    if isinstance(body, list):
        if body and all(isinstance(b, dict) for b in body):  # a list of maps: any of them
            return _combine("any", [_search(b) for b in body])
        if body and all(isinstance(b, (str, int)) for b in body):  # keywords
            return _combine("any", [{"field": "raw", "op": "contains", "value": str(b)} for b in body])
    raise SigmaError("A search must be a map of fields, a list of maps, or a list of keywords.")


_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")


class _Condition:
    def __init__(self, text: str, searches: dict[str, dict]):
        if "|" in text:
            raise SigmaError("Conditions with aggregation (for example '| count') are not supported.")
        self.tokens = _TOKEN.findall(text)
        self.i, self.searches = 0, searches

    def peek(self):
        return self.tokens[self.i].lower() if self.i < len(self.tokens) else None

    def take(self):
        token = self.tokens[self.i]
        self.i += 1
        return token

    def parse(self) -> dict:
        node = self.parse_or()
        if self.i != len(self.tokens):
            raise SigmaError(f"The condition could not be read near '{self.tokens[self.i]}'.")
        return node

    def parse_or(self):
        items = [self.parse_and()]
        while self.peek() == "or":
            self.take()
            items.append(self.parse_and())
        return _combine("any", items)

    def parse_and(self):
        items = [self.parse_not()]
        while self.peek() == "and":
            self.take()
            items.append(self.parse_not())
        return _combine("all", items)

    def parse_not(self):
        if self.peek() == "not":
            self.take()
            return {"not": self.parse_not()}
        return self.parse_atom()

    def parse_atom(self):
        token = self.peek()
        if token is None:
            raise SigmaError("The condition ends too early.")
        if token == "(":
            self.take()
            node = self.parse_or()
            if self.peek() != ")":
                raise SigmaError("A parenthesis in the condition is not closed.")
            self.take()
            return node
        if token in ("1", "all", "any") and self.i + 1 < len(self.tokens) and self.tokens[self.i + 1].lower() == "of":
            quantifier = self.take().lower()
            self.take()  # "of"
            if self.i >= len(self.tokens):
                raise SigmaError(f"'{quantifier} of' needs the name of a search, or 'them'.")
            pattern = self.take()
            names = list(self.searches) if pattern.lower() == "them" else fnmatch.filter(self.searches, pattern)
            if not names:
                raise SigmaError(f"'{quantifier} of {pattern}' matches no search.")
            return _combine("all" if quantifier == "all" else "any", [self.searches[n] for n in names])
        name = self.take()
        if name not in self.searches:
            raise SigmaError(f"The condition uses '{name}', which is not defined under detection.")
        return self.searches[name]


def convert(text: str) -> dict:
    """Return {"name", "description", "severity", "params"} for a custom rule, or raise SigmaError."""
    if len(text.encode("utf-8", errors="replace")) > MAX_BYTES:
        raise SigmaError("The rule is larger than 100 KB.")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        raise SigmaError("The text is not valid YAML.") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("detection"), dict):
        raise SigmaError("This does not look like a Sigma rule: it needs a title and a detection section.")
    detection = doc["detection"]
    condition = detection.get("condition")
    if isinstance(condition, list):
        condition = " or ".join(f"({c})" for c in condition)
    if not isinstance(condition, str) or not condition.strip():
        raise SigmaError("The rule has no condition.")
    searches = {str(k): _search(v) for k, v in detection.items() if k not in ("condition", "timeframe")}
    if not searches:
        raise SigmaError("The rule defines no searches.")
    tree = _Condition(condition, searches).parse()
    if "field" in tree:
        tree = {"all": [tree]}  # a rule's top level is always a group
    title = " ".join(str(doc.get("title") or "").split())
    if not title:
        raise SigmaError("The rule has no title.")
    description = " ".join(str(doc.get("description") or title).split())
    level = str(doc.get("level") or "medium").lower()
    try:
        params = validate_params({"when": tree, "threshold": 1, "window_minutes": 10, "group_by": "none"})
    except RuleError as exc:
        raise SigmaError(str(exc)) from exc
    return {"name": title[:100], "description": description[:1000], "severity": LEVELS.get(level, "medium"),
            "params": params}
