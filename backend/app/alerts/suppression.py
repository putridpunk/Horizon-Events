"""Known false positives. A suppression matches a detection when every field it sets equals the detection's.

Malware detections (HZ-008) are never suppressed: they come from a file the user chose to scan.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.suppression_models import SuppressionRow
from app.domain import Detection, utcnow

NEVER_SUPPRESSED = ("HZ-008",)


class SuppressionError(ValueError):
    """A request that cannot be accepted; the message is shown to the user."""


def _clean(value: str | None) -> str | None:
    value = (value or "").strip()
    return value or None


class Suppressions:
    def __init__(self, session: Session):
        self.s = session
        self._rows: list[SuppressionRow] | None = None

    def list(self) -> list[SuppressionRow]:
        return list(self.s.scalars(select(SuppressionRow).order_by(SuppressionRow.id.desc())))

    def create(self, rule_id=None, source_ip=None, username=None, note: str = "") -> SuppressionRow:
        rule_id, source_ip, username = _clean(rule_id), _clean(source_ip), _clean(username)
        if not (rule_id or source_ip or username):
            raise SuppressionError("Choose at least a rule, an address or an account; otherwise every alert would be hidden.")
        if rule_id in NEVER_SUPPRESSED:
            raise SuppressionError("Malware detections cannot be suppressed.")
        existing = self.s.scalars(select(SuppressionRow).where(
            SuppressionRow.rule_id.is_(rule_id) if rule_id is None else SuppressionRow.rule_id == rule_id,
            SuppressionRow.source_ip.is_(source_ip) if source_ip is None else SuppressionRow.source_ip == source_ip,
            SuppressionRow.username.is_(username) if username is None else SuppressionRow.username == username)).first()
        if existing:
            return existing
        row = SuppressionRow(rule_id=rule_id, source_ip=source_ip, username=username, note=(note or "").strip()[:500],
                             created_at=utcnow())
        self.s.add(row)
        self.s.flush()
        self._rows = None
        return row

    def delete(self, suppression_id: int) -> bool:
        row = self.s.get(SuppressionRow, suppression_id)
        if row is None:
            return False
        self.s.delete(row)
        self.s.flush()
        self._rows = None
        return True

    def match(self, detection: Detection) -> SuppressionRow | None:
        if detection.rule_id in NEVER_SUPPRESSED:
            return None
        if self._rows is None:
            self._rows = self.list()
        for row in self._rows:
            if ((row.rule_id is None or row.rule_id == detection.rule_id)
                    and (row.source_ip is None or row.source_ip == detection.source_ip)
                    and (row.username is None or row.username == detection.username)):
                return row
        return None

    def record_hit(self, row: SuppressionRow) -> None:
        row.hits += 1
        row.last_hit = utcnow()
