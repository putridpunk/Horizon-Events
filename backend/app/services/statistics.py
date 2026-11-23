"""Aggregate queries for the dashboard. Portable SQL (no dialect-specific date functions)."""
from __future__ import annotations

from collections import Counter
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database.models import AlertRow, DetectionRuleRow, EventRow, LogSourceRow


def _count(session: Session, stmt) -> int:
    return session.scalar(select(func.count()).select_from(stmt.subquery())) or 0


def overview(session: Session) -> dict:
    return {
        "total_events": session.scalar(select(func.count(EventRow.id))) or 0,
        "total_alerts": session.scalar(select(func.count(AlertRow.id))) or 0,
        "open_alerts": _count(session, select(AlertRow).where(AlertRow.status == "OPEN")),
        "critical_alerts": _count(session, select(AlertRow).where(AlertRow.severity == "critical")),
        "high_alerts": _count(session, select(AlertRow).where(AlertRow.severity == "high")),
        "sources": session.scalar(select(func.count(LogSourceRow.id))) or 0,
    }


def events_over_time(session: Session, bucket: str = "hour", start: datetime | None = None,
                     end: datetime | None = None) -> list[dict]:
    if bucket not in ("hour", "day"):
        raise ValueError("bucket must be 'hour' or 'day'")
    stmt = select(EventRow.timestamp)
    if start:
        stmt = stmt.where(EventRow.timestamp >= start)
    if end:
        stmt = stmt.where(EventRow.timestamp <= end)
    fmt = "%Y-%m-%dT%H:00:00" if bucket == "hour" else "%Y-%m-%dT00:00:00"
    counts = Counter(ts.strftime(fmt) for ts in session.scalars(stmt))
    return [{"t": t, "count": c} for t, c in sorted(counts.items())]


def _top(session: Session, column, limit: int, start=None, end=None) -> list[dict]:
    stmt = select(column, func.count()).where(column.is_not(None))
    if start:
        stmt = stmt.where(EventRow.timestamp >= start)
    if end:
        stmt = stmt.where(EventRow.timestamp <= end)
    rows = session.execute(stmt.group_by(column).order_by(func.count().desc(), column).limit(limit))
    return [{"name": name, "count": count} for name, count in rows]


def top_event_types(session: Session, limit: int = 10, start=None, end=None) -> list[dict]:
    return _top(session, EventRow.event_type, limit, start, end)


def top_source_ips(session: Session, limit: int = 10, start=None, end=None) -> list[dict]:
    return _top(session, EventRow.source_ip, limit, start, end)


def alert_severity_distribution(session: Session, start=None, end=None) -> list[dict]:
    stmt = select(AlertRow.severity, func.count())
    if start:
        stmt = stmt.where(AlertRow.last_seen >= start)
    if end:
        stmt = stmt.where(AlertRow.last_seen <= end)
    counts = dict(session.execute(stmt.group_by(AlertRow.severity)).all())
    return [{"severity": s, "count": counts.get(s, 0)} for s in ("critical", "high", "medium", "low")]


def alerts_by_rule(session: Session, start=None, end=None) -> dict[str, int]:
    stmt = select(AlertRow.rule_id, func.count())
    if start:
        stmt = stmt.where(AlertRow.last_seen >= start)
    if end:
        stmt = stmt.where(AlertRow.last_seen <= end)
    return dict(session.execute(stmt.group_by(AlertRow.rule_id)).all())


def rule_stats(session: Session, start=None, end=None) -> list[dict]:
    out = []
    for rule in session.scalars(select(DetectionRuleRow).order_by(DetectionRuleRow.id)):
        stmt = select(func.count(AlertRow.id), func.max(AlertRow.last_seen)).where(AlertRow.rule_id == rule.id)
        if start:
            stmt = stmt.where(AlertRow.last_seen >= start)
        if end:
            stmt = stmt.where(AlertRow.last_seen <= end)
        count, last = session.execute(stmt).one()
        out.append({"rule_id": rule.id, "name": rule.name, "severity": rule.severity, "enabled": rule.enabled,
                    "alerts": count, "last_triggered": last.isoformat() if last else None})
    return out
