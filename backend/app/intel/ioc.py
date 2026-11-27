"""Indicators of compromise from files the user chooses: STIX 2.1 bundles, MISP exports, or plain lists.

Nothing is downloaded and nothing is sent anywhere: the file is read, its IP addresses, file hashes and domain
names are stored, and alerts are compared with them locally."""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.database.ioc_models import IocRow
from app.database.models import IntelEntryRow, IntelFeedRow
from app.domain import utcnow

MAX_ENTRIES = 200_000
MAX_FEEDS = 20
PREFIX = "user:"
HASH_KINDS = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX = re.compile(r"^[0-9a-f]+$")
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
_STIX_HASH = re.compile(r"hashes\.'?(?:SHA-?256|SHA-?1|MD5)'?\s*=\s*'([0-9A-Fa-f]{32,64})'", re.I)
_STIX_VALUE = re.compile(r"(domain-name|hostname|ipv4-addr|ipv6-addr|url):value\s*=\s*'((?:[^'\\]|\\.)*)'", re.I)
_SHA256_IN_TEXT = re.compile(r"\b[0-9a-fA-F]{64}\b")
_DOMAIN_IN_TEXT = re.compile(r"(?<![a-z0-9-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62})(?![a-z0-9-])", re.I)


class IocError(ValueError):
    """A file that cannot be used; the message is shown to the user."""


@dataclass
class Indicators:
    ips: set[str] = field(default_factory=set)
    hashes: set[tuple[str, str]] = field(default_factory=set)  # (kind, value)
    domains: set[str] = field(default_factory=set)
    skipped: int = 0

    @property
    def total(self) -> int:
        return len(self.ips) + len(self.hashes) + len(self.domains)

    def add(self, value: str | None) -> None:
        """Classify one value and keep it if it is an address, hash or domain."""
        v = (value or "").strip().strip("'\"").lower().removeprefix("*.")
        if not v:
            return
        if "://" in v:
            v = (urlparse(v).hostname or "").lower()
        elif "/" in v and not _is_network(v):
            v = v.split("/", 1)[0]
        if _is_network(v):
            self.ips.add(str(ipaddress.ip_network(v, strict=False)))
        elif _HEX.match(v) and len(v) in HASH_KINDS:
            self.hashes.add((HASH_KINDS[len(v)], v))
        elif _DOMAIN.match(v):
            self.domains.add(v.removeprefix("*."))
        else:
            self.skipped += 1


def _is_network(v: str) -> bool:
    try:
        ipaddress.ip_network(v, strict=False)
        return True
    except ValueError:
        return False


# ---- formats ---------------------------------------------------------------------------------------------------
_MISP_PLAIN = {"ip-src", "ip-dst", "domain", "hostname", "url", "sha256", "sha1", "md5", "uri"}
_MISP_PAIR = {"filename|sha256": 1, "filename|sha1": 1, "filename|md5": 1, "domain|ip": 0}


def _walk(node, found: Indicators) -> None:
    if isinstance(node, list):
        for item in node:
            _walk(item, found)
    elif isinstance(node, dict):
        kind = node.get("type")
        if kind == "indicator" and isinstance(node.get("pattern"), str):  # STIX indicator
            pattern = node["pattern"]
            for value in _STIX_HASH.findall(pattern):
                found.add(value)
            for _, value in _STIX_VALUE.findall(pattern):
                found.add(value.replace("\\'", "'"))
        elif kind in ("domain-name", "ipv4-addr", "ipv6-addr", "url") and isinstance(node.get("value"), str):
            found.add(node["value"])  # STIX observable
        elif kind == "file" and isinstance(node.get("hashes"), dict):
            for value in node["hashes"].values():
                found.add(str(value))
        elif isinstance(kind, str) and "value" in node and "category" in node:  # MISP attribute
            value = str(node.get("value", ""))
            if kind in _MISP_PLAIN:
                found.add(value)
            elif kind in _MISP_PAIR:
                parts = value.split("|")
                found.add(parts[_MISP_PAIR[kind]] if len(parts) > _MISP_PAIR[kind] else "")
        for child in node.values():
            if isinstance(child, (dict, list)):
                _walk(child, found)


def parse_indicators(text: str) -> Indicators:
    """Read a STIX bundle, a MISP export (both JSON) or a plain list with one indicator per line."""
    text = text.strip().lstrip("﻿")
    if not text:
        raise IocError("The file is empty.")
    found = Indicators()
    if text[0] in "{[":
        try:
            _walk(json.loads(text), found)
        except ValueError:
            raise IocError("The file looks like JSON but could not be read as STIX or MISP.") from None
    else:
        for line in text.splitlines():
            line = line.split("#", 1)[0].split(";", 1)[0].strip()
            if line:
                found.add(re.split(r"[,\s]+", line, maxsplit=1)[0])
    if found.total == 0:
        raise IocError("No IP addresses, file hashes or domain names were found in the file.")
    if found.total > MAX_ENTRIES:
        raise IocError(f"The file has more than {MAX_ENTRIES:,} indicators; split it into smaller lists.")
    return found


# ---- storing ---------------------------------------------------------------------------------------------------
def feed_id_for(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40]
    if not slug:
        raise IocError("Give the list a name made of letters or digits.")
    return PREFIX + slug


def import_list(session: Session, name: str, text: str) -> dict:
    """Store a list as a custom feed, replacing an earlier list with the same name."""
    name = " ".join(name.split())
    if not name or len(name) > 100:
        raise IocError("Give the list a name of up to 100 characters.")
    fid = feed_id_for(name)
    found = parse_indicators(text)
    exists = session.get(IntelFeedRow, fid) is not None
    custom = session.scalar(select(func.count()).select_from(IntelFeedRow).where(IntelFeedRow.id.like(f"{PREFIX}%"))) or 0
    if not exists and custom >= MAX_FEEDS:
        raise IocError(f"You can keep at most {MAX_FEEDS} imported lists. Remove one first.")
    session.execute(delete(IntelEntryRow).where(IntelEntryRow.feed_id == fid))
    session.execute(delete(IocRow).where(IocRow.feed_id == fid))
    row = session.get(IntelFeedRow, fid) or IntelFeedRow(id=fid, name=name, source="custom")
    row.name, row.source, row.fetched_at, row.entries = name, "custom", utcnow(), found.total
    session.add(row)
    session.flush()  # the feed must exist before its entries (foreign keys are enforced on PostgreSQL)
    session.add_all(IntelEntryRow(feed_id=fid, cidr=c) for c in sorted(found.ips))
    session.add_all(IocRow(feed_id=fid, kind=k, value=v) for k, v in sorted(found.hashes))
    session.add_all(IocRow(feed_id=fid, kind="domain", value=d) for d in sorted(found.domains))
    session.commit()
    return {"feed": fid, "name": name, "ips": len(found.ips), "hashes": len(found.hashes),
            "domains": len(found.domains), "skipped": found.skipped, "replaced": exists}


def delete_list(session: Session, feed_id: str) -> bool:
    """Remove an imported list. The built-in feeds cannot be removed here."""
    if not feed_id.startswith(PREFIX):
        raise IocError("Only lists you imported can be removed.")
    row = session.get(IntelFeedRow, feed_id)
    if row is None:
        return False
    session.execute(delete(IntelEntryRow).where(IntelEntryRow.feed_id == feed_id))
    session.execute(delete(IocRow).where(IocRow.feed_id == feed_id))
    session.delete(row)
    session.commit()
    return True


# ---- matching --------------------------------------------------------------------------------------------------
def _candidate_domains(text: str) -> set[str]:
    out: set[str] = set()
    for match in _DOMAIN_IN_TEXT.findall(text.lower()):
        labels = match.split(".")
        out.update(".".join(labels[i:]) for i in range(len(labels) - 1))  # a.b.evil.com also tries b.evil.com, evil.com
    return out


def find_matches(session: Session, text: str, hashes: list[str] | None = None) -> list[dict]:
    """File hashes and domains in `text` (and the given hashes) that are on an imported list."""
    wanted = {h.lower() for h in (hashes or []) if h} | {h.lower() for h in _SHA256_IN_TEXT.findall(text)}
    values = wanted | _candidate_domains(text)
    if not values:
        return []
    names = {f.id: f.name for f in session.scalars(select(IntelFeedRow))}
    rows = session.execute(select(IocRow.kind, IocRow.value, IocRow.feed_id).where(IocRow.value.in_(sorted(values)))).all()
    return [{"kind": k, "value": v, "feed": names.get(f, f)} for k, v, f in sorted(rows)]
