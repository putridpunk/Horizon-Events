"""Feed storage, user-triggered refresh and local enrichment of IPs.

The only network access is `http_fetch`, called from `refresh_feeds` when the user asks for it.
Matching is done locally, so no IP from the logs ever leaves the machine.
"""
from __future__ import annotations

import urllib.request
from datetime import timedelta
from typing import Callable

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.database.models import IntelEntryRow, IntelFeedRow
from app.domain import utcnow
from app.intel.feeds import FEEDS, PARSERS, IpMatcher

MIN_REFRESH = timedelta(minutes=60)
MAX_BYTES = 10_485_760

DEMO_FEED_ID = "demo"
DEMO_FEED_NAME = "Synthetic demo feed (not real intelligence)"
DEMO_ENTRIES = ["198.51.100.77/32", "203.0.113.7/32", "203.0.113.99/32"]  # reserved documentation addresses


def http_fetch(url: str, timeout: int = 20, max_bytes: int = MAX_BYTES) -> str:
    """Download a feed (https only, size-capped, generic User-Agent)."""
    if not url.startswith("https://"):
        raise ValueError("Only https feed URLs are allowed")
    request = urllib.request.Request(url, headers={"User-Agent": "HorizonEvents/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("Feed response exceeds the size limit")
    return data.decode("utf-8", errors="replace")


def _store(session: Session, feed_id: str, name: str, source: str, cidrs: list[str], fetched_at) -> None:
    session.execute(delete(IntelEntryRow).where(IntelEntryRow.feed_id == feed_id))
    row = session.get(IntelFeedRow, feed_id) or IntelFeedRow(id=feed_id, name=name, source=source)
    row.name, row.source, row.fetched_at, row.entries = name, source, fetched_at, len(cidrs)
    session.add(row)
    session.flush()  # the feed row must exist before its entries (foreign keys are enforced on PostgreSQL)
    session.add_all(IntelEntryRow(feed_id=feed_id, cidr=c) for c in cidrs)
    session.commit()


def refresh_feeds(session: Session, feed_ids: list[str] | None = None,
                  fetch: Callable[[str], str] = http_fetch, now: Callable = utcnow) -> list[dict]:
    """Download and store the requested feeds (default: all). Raises ValueError for unknown feed ids."""
    ids = feed_ids or list(FEEDS)
    unknown = [i for i in ids if i not in FEEDS]
    if unknown:
        raise ValueError(f"Unknown feed: {', '.join(unknown)}")
    results = []
    for fid in ids:
        current = session.get(IntelFeedRow, fid)
        if current and current.fetched_at and now() - current.fetched_at < MIN_REFRESH:
            results.append({"feed": fid, "status": "too_soon", "entries": current.entries,
                            "message": "Refreshed less than an hour ago; try again later."})
            continue
        try:
            cidrs = PARSERS[fid](fetch(FEEDS[fid]["url"]))
        except Exception as exc:  # network, size or parse failure: keep the previous entries
            results.append({"feed": fid, "status": "error", "entries": current.entries if current else 0,
                            "message": f"{type(exc).__name__}: {exc}"})
            continue
        _store(session, fid, FEEDS[fid]["name"], "network", cidrs, now())
        results.append({"feed": fid, "status": "updated", "entries": len(cidrs), "message": "Updated."})
    return results


def ensure_demo_feed(session: Session) -> bool:
    """Load the synthetic demo feed when no feed is stored yet. Returns True if it loaded."""
    if session.scalar(select(func.count()).select_from(IntelFeedRow)):
        return False
    _store(session, DEMO_FEED_ID, DEMO_FEED_NAME, "demo", DEMO_ENTRIES, None)
    return True


def feed_status(session: Session) -> list[dict]:
    rows = session.scalars(select(IntelFeedRow).order_by(IntelFeedRow.id))
    return [{"id": r.id, "name": r.name, "source": r.source, "entries": r.entries,
             "fetched_at": r.fetched_at.isoformat() if r.fetched_at else None,
             "description": FEEDS.get(r.id, {}).get(
                 "description", "A list you imported from a file." if r.source == "custom"
                 else "Synthetic data for demonstrations only.")}
            for r in rows]


_cache: dict = {"key": None, "value": None}


def _matcher(session: Session) -> tuple[IpMatcher, dict[str, str]]:
    feeds = list(session.scalars(select(IntelFeedRow).order_by(IntelFeedRow.id)))
    entry_state = session.execute(select(func.count(IntelEntryRow.id), func.max(IntelEntryRow.id))).one()
    key = (tuple((f.id, f.fetched_at, f.entries) for f in feeds), tuple(entry_state))
    if _cache["key"] != key:
        entries: dict[str, list[str]] = {f.id: [] for f in feeds}
        for feed_id, cidr in session.execute(select(IntelEntryRow.feed_id, IntelEntryRow.cidr)):
            entries[feed_id].append(cidr)
        _cache.update(key=key, value=(IpMatcher(entries), {f.id: f.name for f in feeds}))
    return _cache["value"]


def enrich(session: Session, ip: str | None, _matcher_fn=None) -> dict:
    matcher, names = (_matcher_fn or _matcher)(session)
    hits = matcher.lookup(ip)
    return {"listed": bool(hits), "feeds": [{"id": h, "name": names.get(h, h)} for h in hits]}
