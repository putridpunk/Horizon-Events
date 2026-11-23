"""Incident queries. Like the other repositories, it flushes but never commits."""
from __future__ import annotations

from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from app.database.incident_models import (IncidentAlertLink, IncidentExclusionRow, IncidentHistoryRow,
                                          IncidentRow)
from app.database.models import AlertRow
from app.domain import utcnow


class IncidentRepository:
    def __init__(self, session: Session):
        self.s = session

    def create(self, **fields) -> IncidentRow:
        row = IncidentRow(**fields)
        self.s.add(row)
        self.s.flush()
        row.code = f"INC-{row.id:06d}"
        self.s.flush()
        return row

    def get(self, incident_id: int) -> IncidentRow | None:
        return self.s.get(IncidentRow, incident_id)

    def get_alert(self, alert_id: int) -> AlertRow | None:
        return self.s.get(AlertRow, alert_id)

    def list(self, status=None, severity=None, limit: int = 50, offset: int = 0) -> tuple[list[IncidentRow], int]:
        stmt = select(IncidentRow)
        if status:
            stmt = stmt.where(IncidentRow.status == status)
        if severity:
            stmt = stmt.where(IncidentRow.severity == severity)
        total = self.s.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        order = case((IncidentRow.severity == "critical", 4), (IncidentRow.severity == "high", 3),
                     (IncidentRow.severity == "medium", 2), else_=1)
        rows = self.s.scalars(stmt.order_by(order.desc(), IncidentRow.last_activity.desc(), IncidentRow.id.desc())
                              .limit(limit).offset(offset)).all()
        return list(rows), total

    def incident_for_alert(self, alert_id: int) -> IncidentRow | None:
        link = self.s.get(IncidentAlertLink, alert_id)
        return self.s.get(IncidentRow, link.incident_id) if link else None

    def alerts_of(self, incident_id: int) -> list[AlertRow]:
        return list(self.s.scalars(
            select(AlertRow).join(IncidentAlertLink, IncidentAlertLink.alert_id == AlertRow.id)
            .where(IncidentAlertLink.incident_id == incident_id).order_by(AlertRow.last_seen, AlertRow.id)))

    def alert_count(self, incident_id: int) -> int:
        return self.s.scalar(select(func.count()).select_from(IncidentAlertLink)
                             .where(IncidentAlertLink.incident_id == incident_id)) or 0

    def candidates(self, source_ip, username, since, until) -> list[IncidentRow]:
        """Open (not RESOLVED) incidents that contain an alert with the same IP or username and whose
        last activity falls inside [since, until], lowest id first."""
        keys = []
        if source_ip:
            keys.append(AlertRow.source_ip == source_ip)
        if username:
            keys.append(AlertRow.username == username)
        if not keys:
            return []
        stmt = (select(IncidentRow).join(IncidentAlertLink, IncidentAlertLink.incident_id == IncidentRow.id)
                .join(AlertRow, AlertRow.id == IncidentAlertLink.alert_id)
                .where(IncidentRow.status != "RESOLVED", IncidentRow.last_activity >= since,
                       IncidentRow.last_activity <= until, or_(*keys))
                .distinct().order_by(IncidentRow.id))
        return list(self.s.scalars(stmt))

    def link(self, incident_id: int, alert_id: int, added_by: str) -> None:
        self.s.add(IncidentAlertLink(alert_id=alert_id, incident_id=incident_id, added_by=added_by))
        self.s.flush()

    def unlink(self, alert_id: int) -> None:
        link = self.s.get(IncidentAlertLink, alert_id)
        if link:
            self.s.delete(link)
            self.s.flush()

    def is_excluded(self, alert_id: int) -> bool:
        return self.s.get(IncidentExclusionRow, alert_id) is not None

    def exclude(self, alert_id: int) -> None:
        if not self.is_excluded(alert_id):
            self.s.add(IncidentExclusionRow(alert_id=alert_id))
            self.s.flush()

    def unexclude(self, alert_id: int) -> None:
        row = self.s.get(IncidentExclusionRow, alert_id)
        if row:
            self.s.delete(row)
            self.s.flush()

    def unassigned_alerts(self) -> list[AlertRow]:
        """Alerts with an IP or username that are in no incident and were not removed by an analyst."""
        linked = select(IncidentAlertLink.alert_id)
        excluded = select(IncidentExclusionRow.alert_id)
        return list(self.s.scalars(
            select(AlertRow).where(AlertRow.id.not_in(linked), AlertRow.id.not_in(excluded),
                                   or_(AlertRow.source_ip.is_not(None), AlertRow.username.is_not(None)))
            .order_by(AlertRow.last_seen, AlertRow.id)))

    def add_history(self, incident_id: int, action: str, detail: str | None = None,
                    from_status: str | None = None, to_status: str | None = None) -> IncidentHistoryRow:
        row = IncidentHistoryRow(incident_id=incident_id, action=action, detail=detail,
                                 from_status=from_status, to_status=to_status, at=utcnow())
        self.s.add(row)
        self.s.flush()
        return row

    def history(self, incident_id: int) -> list[IncidentHistoryRow]:
        return list(self.s.scalars(select(IncidentHistoryRow).where(IncidentHistoryRow.incident_id == incident_id)
                                   .order_by(IncidentHistoryRow.at, IncidentHistoryRow.id)))
