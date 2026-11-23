"""Repositories: the only place SQL is issued. They flush but never commit."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from app.database.models import (AlertEventLink, AlertHistoryRow, AlertRow, DetectionRuleRow, EventRow,
                                 LogSourceRow)
from app.domain import Event, EventType, Severity, utcnow

_SEV_ORDER = case(
    (AlertRow.severity == "critical", 4), (AlertRow.severity == "high", 3),
    (AlertRow.severity == "medium", 2), else_=1)


def row_to_event(r: EventRow) -> Event:
    return Event(
        timestamp=r.timestamp, source=r.source, event_type=EventType(r.event_type), severity=Severity(r.severity),
        message=r.message, raw=r.raw, username=r.username, source_ip=r.source_ip, host=r.host,
        service=r.service, metadata=r.extra or {}, id=r.id)


class EventRepository:
    def __init__(self, session: Session):
        self.s = session

    def add_many(self, events: list[Event], source_id: int | None = None) -> list[Event]:
        """Insert events not seen before (by fingerprint). Returns the newly stored events with ids."""
        prints = {e.fingerprint(): e for e in events}
        existing: set[str] = set()
        keys = list(prints)
        for i in range(0, len(keys), 500):
            chunk = keys[i:i + 500]
            existing.update(self.s.scalars(select(EventRow.fingerprint).where(EventRow.fingerprint.in_(chunk))))
        new_rows = []
        for fp, e in prints.items():
            if fp in existing:
                continue
            new_rows.append(EventRow(
                fingerprint=fp, timestamp=e.timestamp, source=e.source, event_type=e.event_type.value,
                severity=e.severity.value, username=e.username, source_ip=e.source_ip, host=e.host,
                service=e.service, message=e.message, raw=e.raw, extra=e.metadata, source_id=source_id))
        self.s.add_all(new_rows)
        self.s.flush()
        return [row_to_event(r) for r in new_rows]

    def _filtered(self, q=None, source=None, event_type=None, severity=None, start=None, end=None):
        stmt = select(EventRow)
        if q:
            like = f"%{q}%"
            stmt = stmt.where(or_(EventRow.message.ilike(like), EventRow.username.ilike(like),
                                  EventRow.source_ip.ilike(like), EventRow.host.ilike(like),
                                  EventRow.raw.ilike(like)))
        if source:
            stmt = stmt.where(EventRow.source == source)
        if event_type:
            stmt = stmt.where(EventRow.event_type == event_type)
        if severity:
            stmt = stmt.where(EventRow.severity == severity)
        if start:
            stmt = stmt.where(EventRow.timestamp >= start)
        if end:
            stmt = stmt.where(EventRow.timestamp <= end)
        return stmt

    def search(self, q=None, source=None, event_type=None, severity=None, start=None, end=None,
               limit: int = 50, offset: int = 0) -> tuple[list[EventRow], int]:
        stmt = self._filtered(q, source, event_type, severity, start, end)
        total = self.s.scalar(select(func.count()).select_from(stmt.subquery()))
        rows = self.s.scalars(stmt.order_by(EventRow.timestamp.desc(), EventRow.id.desc())
                              .limit(limit).offset(offset)).all()
        return list(rows), total or 0

    def get(self, event_id: int) -> EventRow | None:
        return self.s.get(EventRow, event_id)

    def events_in_window(self, event_types: list[EventType], since: datetime, until: datetime,
                         source_ip: str | None = None, username: str | None = None,
                         service: str | None = None) -> list[Event]:
        stmt = select(EventRow).where(EventRow.event_type.in_([t.value for t in event_types]),
                                      EventRow.timestamp >= since, EventRow.timestamp <= until)
        if source_ip:
            stmt = stmt.where(EventRow.source_ip == source_ip)
        if username:
            stmt = stmt.where(EventRow.username == username)
        if service:
            stmt = stmt.where(EventRow.service == service)
        return [row_to_event(r) for r in self.s.scalars(stmt.order_by(EventRow.timestamp))]

    def count_in_window(self, event_types: list[EventType], since: datetime, until: datetime,
                        source_ip: str | None = None, username: str | None = None,
                        service: str | None = None) -> int:
        return len(self.events_in_window(event_types, since, until, source_ip, username, service))


class SourceRepository:
    def __init__(self, session: Session):
        self.s = session

    def create(self, name: str, source_type: str) -> LogSourceRow:
        row = LogSourceRow(name=name, source_type=source_type)
        self.s.add(row)
        self.s.flush()
        return row

    def list(self) -> list[LogSourceRow]:
        return list(self.s.scalars(select(LogSourceRow).order_by(LogSourceRow.id.desc())))


class RuleRepository:
    def __init__(self, session: Session):
        self.s = session

    def seed_defaults(self, defaults: list[dict]) -> None:
        if self.s.scalar(select(func.count()).select_from(DetectionRuleRow)):
            return
        for d in defaults:
            self.s.add(DetectionRuleRow(**d))
        self.s.flush()

    def list(self) -> list[DetectionRuleRow]:
        return list(self.s.scalars(select(DetectionRuleRow).order_by(DetectionRuleRow.id)))

    def get(self, rule_id: str) -> DetectionRuleRow | None:
        return self.s.get(DetectionRuleRow, rule_id)

    def update(self, rule_id: str, **fields) -> DetectionRuleRow | None:
        row = self.get(rule_id)
        if row is None:
            return None
        for k, v in fields.items():
            if v is not None:
                setattr(row, k, v)
        self.s.flush()
        return row


class AlertRepository:
    def __init__(self, session: Session):
        self.s = session

    def create(self, **fields) -> AlertRow:
        row = AlertRow(**fields)
        self.s.add(row)
        self.s.flush()
        row.alert_code = f"ALT-{row.id:06d}"
        self.s.flush()
        return row

    def get(self, alert_id: int) -> AlertRow | None:
        return self.s.get(AlertRow, alert_id)

    def find_active_by_key(self, key: str, since: datetime) -> AlertRow | None:
        return self.s.scalars(
            select(AlertRow).where(AlertRow.key == key, AlertRow.status.in_(["OPEN", "INVESTIGATING"]),
                                   AlertRow.last_seen >= since).order_by(AlertRow.id.desc())).first()

    def list(self, severity=None, status=None, rule_id=None, limit: int = 50, offset: int = 0
             ) -> tuple[list[AlertRow], int]:
        stmt = select(AlertRow)
        if severity:
            stmt = stmt.where(AlertRow.severity == severity)
        if status:
            stmt = stmt.where(AlertRow.status == status)
        if rule_id:
            stmt = stmt.where(AlertRow.rule_id == rule_id)
        total = self.s.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        rows = self.s.scalars(stmt.order_by(_SEV_ORDER.desc(), AlertRow.last_seen.desc(), AlertRow.id.desc())
                              .limit(limit).offset(offset)).all()
        return list(rows), total

    def add_history(self, alert_id: int, from_status: str | None, to_status: str, note: str | None = None,
                    at: datetime | None = None) -> AlertHistoryRow:
        row = AlertHistoryRow(alert_id=alert_id, from_status=from_status, to_status=to_status, note=note,
                              at=at or utcnow())
        self.s.add(row)
        self.s.flush()
        return row

    def history(self, alert_id: int) -> list[AlertHistoryRow]:
        return list(self.s.scalars(select(AlertHistoryRow).where(AlertHistoryRow.alert_id == alert_id)
                                   .order_by(AlertHistoryRow.at, AlertHistoryRow.id)))

    def link_events(self, alert_id: int, event_ids: list[int]) -> None:
        have = set(self.s.scalars(select(AlertEventLink.event_id).where(AlertEventLink.alert_id == alert_id)))
        for eid in set(event_ids) - have:
            self.s.add(AlertEventLink(alert_id=alert_id, event_id=eid))
        self.s.flush()

    def linked_events(self, alert_id: int) -> list[EventRow]:
        return list(self.s.scalars(
            select(EventRow).join(AlertEventLink, AlertEventLink.event_id == EventRow.id)
            .where(AlertEventLink.alert_id == alert_id).order_by(EventRow.timestamp)))
