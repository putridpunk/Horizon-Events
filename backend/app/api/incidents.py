from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.alerts.manager import InvalidTransition
from app.api.schemas import alert_out
from app.database.connection import get_session
from app.database.incident_models import IncidentHistoryRow, IncidentRow
from app.database.incident_repository import IncidentRepository
from app.database.repositories import AlertRepository
from app.domain import AlertStatus
from app.incidents.manager import IncidentManager
from app.intel.service import enrich
from app.mitre import techniques_for_rule

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


class IncidentUpdate(BaseModel):
    status: AlertStatus | None = None
    title: str | None = None
    note: str | None = None


class NoteBody(BaseModel):
    text: str


class AlertRef(BaseModel):
    alert_id: int


class MergeBody(BaseModel):
    into: int


def _summary(repo: IncidentRepository, r: IncidentRow) -> dict:
    return {"id": r.id, "incident_id": r.code, "title": r.title, "severity": r.severity, "status": r.status,
            "alert_count": repo.alert_count(r.id), "created_at": r.created_at.isoformat(),
            "last_activity": r.last_activity.isoformat()}


def _history(h: IncidentHistoryRow) -> dict:
    return {"action": h.action, "detail": h.detail, "from_status": h.from_status, "to_status": h.to_status,
            "at": h.at.isoformat()}


def _detail(session: Session, repo: IncidentRepository, row: IncidentRow) -> dict:
    alerts = repo.alerts_of(row.id)
    alert_repo = AlertRepository(session)
    event_times = [e.timestamp for a in alerts for e in alert_repo.linked_events(a.id)]
    techniques: dict[str, dict] = {}
    for a in alerts:
        for t in techniques_for_rule(a.rule_id):
            techniques.setdefault(t["id"], t)
    return {
        **_summary(repo, row),
        "alerts": [{**alert_out(a), "intel": enrich(session, a.source_ip)} for a in alerts],
        "history": [_history(h) for h in repo.history(row.id)],
        "ips": sorted({a.source_ip for a in alerts if a.source_ip}),
        "accounts": sorted({a.username for a in alerts if a.username}),
        "techniques": list(techniques.values()),
        "first_activity": min(event_times).isoformat() if event_times else None,
    }


def _run(session: Session, action):
    """Run a manager action, translating domain errors to HTTP errors and committing on success."""
    try:
        result = action()
    except LookupError as exc:
        raise HTTPException(404, str(exc))
    except (InvalidTransition, ValueError) as exc:
        session.rollback()
        raise HTTPException(422, str(exc))
    session.commit()
    return result


@router.get("")
def list_incidents(status: str | None = None, severity: str | None = None,
                   limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
                   session: Session = Depends(get_session)):
    repo = IncidentRepository(session)
    rows, total = repo.list(status, severity, limit, offset)
    return {"items": [_summary(repo, r) for r in rows], "total": total}


@router.get("/{incident_id}")
def get_incident(incident_id: int, session: Session = Depends(get_session)):
    repo = IncidentRepository(session)
    row = repo.get(incident_id)
    if row is None:
        raise HTTPException(404, "Incident not found")
    return _detail(session, repo, row)


@router.patch("/{incident_id}")
def update_incident(incident_id: int, body: IncidentUpdate, session: Session = Depends(get_session)):
    if body.title is not None and not body.title.strip():
        raise HTTPException(422, "Title must not be empty")
    repo = IncidentRepository(session)
    manager = IncidentManager(repo)

    def action():
        row = None
        if body.status is not None:  # validated first: nothing else is applied if the transition is illegal
            row = manager.change_status(incident_id, body.status, body.note)
        elif body.note:
            row = manager.add_note(incident_id, body.note)
        if body.title is not None:
            row = manager.set_title(incident_id, body.title)
        return row or manager._get(incident_id)

    row = _run(session, action)
    return _detail(session, repo, row)


@router.post("/{incident_id}/notes")
def add_note(incident_id: int, body: NoteBody, session: Session = Depends(get_session)):
    repo = IncidentRepository(session)
    row = _run(session, lambda: IncidentManager(repo).add_note(incident_id, body.text))
    return _detail(session, repo, row)


@router.post("/{incident_id}/alerts")
def add_alert(incident_id: int, body: AlertRef, session: Session = Depends(get_session)):
    repo = IncidentRepository(session)
    row = _run(session, lambda: IncidentManager(repo).add_alert(incident_id, body.alert_id))
    return _detail(session, repo, row)


@router.delete("/{incident_id}/alerts/{alert_id}")
def remove_alert(incident_id: int, alert_id: int, session: Session = Depends(get_session)):
    repo = IncidentRepository(session)
    row = _run(session, lambda: IncidentManager(repo).remove_alert(incident_id, alert_id))
    return _detail(session, repo, row)


@router.post("/{incident_id}/merge")
def merge(incident_id: int, body: MergeBody, session: Session = Depends(get_session)):
    repo = IncidentRepository(session)
    row = _run(session, lambda: IncidentManager(repo).merge(incident_id, body.into))
    return _detail(session, repo, row)
