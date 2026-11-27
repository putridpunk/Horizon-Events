"""The event search language.

    failed login                     words: every word must appear in the message, account, address, host or log line
    "invalid user"                   a quoted phrase
    user:admin ip:203.0.113.7        fields (all must match)
    ip:10.0.0.0/8  ip:192.168.1.*    an address block (/8, /16, /24) or a wildcard
    type:authentication_failure      one event type
    severity:>=high                  one severity, or at least / at most one (>=, <=, >, <)
    since:2026-11-01 until:2026-11-02  a time range (a date alone means the whole day)
    -user:root  NOT ip:10.*          leave out what matches
    user:alice OR user:bob           either side may match (AND binds tighter than OR)

There are no parentheses. Fields: user, ip, host, service, source, type, severity, message, since, until.
The text is turned into a SQL condition with bound parameters only; nothing is ever pasted into SQL.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, time, timedelta

from sqlalchemy import and_, func, not_, or_
from sqlalchemy.sql.elements import ColumnElement

from app.database.models import EventRow
from app.domain import SEVERITY_RANK, EventType, Severity

MAX_LENGTH = 500
MAX_TERMS = 20
SEVERITY_ORDER = [s for s, _ in sorted(SEVERITY_RANK.items(), key=lambda kv: kv[1])]

TEXT_FIELDS = {"user": EventRow.username, "host": EventRow.host, "service": EventRow.service,
               "source": EventRow.source, "message": EventRow.message}
FIELD_NAMES = sorted([*TEXT_FIELDS, "ip", "type", "severity", "since", "until"])
_TOKEN = re.compile(r'''\s*(?:(?P<neg>-)?(?:(?P<field>[A-Za-z]+):)?(?:"(?P<quoted>[^"]*)"|(?P<word>[^\s"]+))|(?P<bad>"))''')


class SearchError(ValueError):
    """A search that cannot be understood; the message says why, in plain words."""


def _like(value: str) -> tuple[str, bool]:
    """(pattern, has_wildcard): `*` is the only wildcard; `%`, `_` and the escape character stay literal."""
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return escaped.replace("*", "%"), "*" in value


def _text_equals(column, value: str) -> ColumnElement:
    column = func.coalesce(column, "")  # a missing value never matches, and so "-user:x" keeps events without a user
    pattern, wild = _like(value)
    if wild:
        return column.ilike(pattern, escape="\\")
    return func.lower(column) == value.lower()


def _contains(column, value: str) -> ColumnElement:
    pattern, _ = _like(value)
    return func.coalesce(column, "").ilike(f"%{pattern}%", escape="\\")


def _any_text(value: str) -> ColumnElement:
    return or_(*[_contains(c, value) for c in (EventRow.message, EventRow.username, EventRow.source_ip,
                                                 EventRow.host, EventRow.raw)])


def _ip(value: str) -> ColumnElement:
    if "/" in value:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise SearchError(f"'{value}' is not a valid address block.") from None
        if net.version != 4 or net.prefixlen not in (8, 16, 24, 32):
            raise SearchError("Address blocks can be IPv4 /8, /16, /24 or /32 (for example ip:10.0.0.0/8). "
                              "Use a wildcard such as ip:10.1.* for other ranges.")
        octets = str(net.network_address).split(".")[: net.prefixlen // 8]
        if net.prefixlen == 32:
            return func.coalesce(EventRow.source_ip, "") == str(net.network_address)
        return func.coalesce(EventRow.source_ip, "").like(".".join(octets) + ".%")
    return _text_equals(EventRow.source_ip, value)


def _severity(value: str) -> ColumnElement:
    match = re.fullmatch(r"(>=|<=|>|<)?\s*([A-Za-z]+)", value.strip())
    if not match or match[2].lower() not in {s.value for s in SEVERITY_ORDER}:
        raise SearchError(f"Severity must be one of {', '.join(s.value for s in SEVERITY_ORDER)}, "
                          "optionally with >=, <=, > or < (for example severity:>=high).")
    op, level = match[1], Severity(match[2].lower())
    rank = SEVERITY_RANK[level]
    wanted = {"": lambda r: r == rank, ">=": lambda r: r >= rank, "<=": lambda r: r <= rank,
              ">": lambda r: r > rank, "<": lambda r: r < rank}[op or ""]
    return EventRow.severity.in_([s.value for s in SEVERITY_ORDER if wanted(SEVERITY_RANK[s])])


def _when(value: str, field: str) -> ColumnElement:
    try:
        if len(value) <= 10:
            day = datetime.combine(datetime.fromisoformat(value).date(), time.min)
            moment = day if field == "since" else day + timedelta(days=1) - timedelta(microseconds=1)
        else:
            moment = datetime.fromisoformat(value.replace("Z", ""))
    except ValueError:
        raise SearchError(f"'{value}' is not a date. Use 2026-11-23 or 2026-11-23T14:30.") from None
    return EventRow.timestamp >= moment if field == "since" else EventRow.timestamp <= moment


def _term(field: str | None, value: str) -> ColumnElement:
    if field is None:
        return _any_text(value)
    if field in TEXT_FIELDS:
        return _contains(TEXT_FIELDS[field], value) if field == "message" else _text_equals(TEXT_FIELDS[field], value)
    if field == "ip":
        return _ip(value)
    if field == "type":
        known = [t.value for t in EventType]
        if value.lower() not in known:
            raise SearchError(f"'{value}' is not an event type. Known types: {', '.join(known)}.")
        return EventRow.event_type == value.lower()
    if field == "severity":
        return _severity(value)
    return _when(value, field)  # since / until


def compile_query(text: str | None) -> ColumnElement | None:
    """Turn search text into a SQL condition, or None for an empty search. Raises SearchError."""
    text = (text or "").strip()
    if not text:
        return None
    if len(text) > MAX_LENGTH:
        raise SearchError(f"A search can have at most {MAX_LENGTH} characters.")
    groups: list[list[ColumnElement]] = [[]]
    pos, terms, negate_next = 0, 0, False
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if m is None or m.end() == pos:
            break
        pos = m.end()
        if m["bad"]:
            raise SearchError('A quotation mark is not closed. Close it with another " or remove it.')
        word = m["word"]
        if m["quoted"] is None and m["field"] is None and not m["neg"]:
            if word == "OR":
                if not groups[-1]:
                    raise SearchError("OR needs a search on both sides.")
                groups.append([])
                continue
            if word == "AND":
                continue
            if word == "NOT":
                negate_next = True
                continue
        value = m["quoted"] if m["quoted"] is not None else word
        field = m["field"].lower() if m["field"] else None
        if field is not None and field not in FIELD_NAMES:
            raise SearchError(f"Unknown field '{m['field']}'. Fields: {', '.join(FIELD_NAMES)}. "
                              "To search for text that contains a colon, put it in quotes.")
        if field is None and m["quoted"] is None and re.fullmatch(r"[A-Za-z]+:", word or ""):
            raise SearchError(f"'{word}' needs a value after the colon (for example {word}admin).")
        if value == "":
            raise SearchError(f"'{field}:' needs a value after the colon." if field else "Empty quotation marks.")
        terms += 1
        if terms > MAX_TERMS:
            raise SearchError(f"A search can have at most {MAX_TERMS} terms.")
        cond = _term(field, value)
        groups[-1].append(not_(cond) if (m["neg"] or negate_next) else cond)
        negate_next = False
    if negate_next or (len(groups) > 1 and not groups[-1]):
        raise SearchError("The search ends in OR or NOT; add what it should apply to.")
    clauses = [and_(*g) for g in groups if g]
    return or_(*clauses) if len(clauses) > 1 else (clauses[0] if clauses else None)
