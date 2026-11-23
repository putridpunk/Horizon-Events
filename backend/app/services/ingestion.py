"""Import orchestration: collect -> store -> detect -> alert. The only place these layers meet."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from app.alerts.manager import AlertManager
from app.collectors.base import collect
from app.database.repositories import AlertRepository, EventRepository, RuleRepository, SourceRepository
from app.detection.engine import DetectionEngine
from app.detection.rules import DEFAULT_RULES


def ensure_default_rules(session: Session) -> None:
    RuleRepository(session).seed_defaults(DEFAULT_RULES)


def import_logs(session: Session, source_type: str, filename: str, content: bytes,
                now: datetime | None = None) -> dict:
    """Raises ValueError for an unknown source_type."""
    events, result = collect(source_type, content, now)
    ensure_default_rules(session)
    source = SourceRepository(session).create(filename, source_type)
    event_repo = EventRepository(session)
    stored = event_repo.add_many(events, source.id)
    source.event_count = len(stored)

    definitions = [
        {"id": r.id, "severity": r.severity, "params": r.params, "enabled": r.enabled}
        for r in RuleRepository(session).list()]
    detections = DetectionEngine.from_definitions(definitions).run(stored, event_repo)
    manager = AlertManager(AlertRepository(session))
    manager.process(detections)
    session.commit()
    return {
        "source_id": source.id, "total": result.total, "imported": len(stored), "skipped": result.skipped,
        "duplicates": result.imported - len(stored), "alerts_created": len(manager.created),
        "alerts_updated": len(manager.updated),
    }
