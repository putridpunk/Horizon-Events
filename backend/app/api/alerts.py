from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.alerts import triage
from app.alerts.manager import AlertManager, InvalidTransition
from app.api.schemas import AlertTriage, AlertUpdate, alert_out, event_out, history_out
from app.database.connection import get_session
from app.database.repositories import AlertRepository
from app.geo.locator import locate
from app.intel.ioc import find_matches
from app.intel.service import enrich
from app.live.bus import bus

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


def _detail(repo: AlertRepository, row) -> dict:
    events = repo.linked_events(row.id)
    hashes = [str((e.extra or {}).get("sha256") or "") for e in events]
    text = " ".join([row.description or "", *(f"{e.message} {e.host or ''} {e.service or ''}" for e in events)])
    return {**alert_out(row), **triage.view(row, repo.s.get(triage.AlertMetaRow, row.id)),
            "intel": enrich(repo.s, row.source_ip), "iocs": find_matches(repo.s, text, hashes),
            "geo": (lambda place: place.as_dict() if place else None)(locate(row.source_ip)),
            "events": [event_out(e) for e in events],
            "history": [history_out(h) for h in repo.history(row.id)]}


@router.get("")
def list_alerts(severity: str | None = None, status: str | None = None, rule_id: str | None = None,
                assignee: str | None = None, tag: str | None = None,
                limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
                session: Session = Depends(get_session)):
    rows, total = AlertRepository(session).list(severity, status, rule_id, limit, offset, assignee, tag)
    metas = triage.metas_for(session, [r.id for r in rows])
    return {"items": [{**alert_out(r), **triage.view(r, metas.get(r.id)), "intel": enrich(session, r.source_ip)}
                      for r in rows], "total": total}


@router.get("/tags")
def list_tags(session: Session = Depends(get_session)):
    return {"tags": triage.all_tags(session), "assignees": triage.all_assignees(session)}


@router.get("/{alert_id}")
def get_alert(alert_id: int, session: Session = Depends(get_session)):
    repo = AlertRepository(session)
    row = repo.get(alert_id)
    if row is None:
        raise HTTPException(404, "Alert not found")
    return _detail(repo, row)


@router.patch("/{alert_id}")
def update_alert(alert_id: int, body: AlertUpdate, session: Session = Depends(get_session)):
    repo = AlertRepository(session)
    try:
        row = AlertManager(repo).change_status(alert_id, body.status, body.note)
    except LookupError:
        raise HTTPException(404, "Alert not found")
    except InvalidTransition as exc:
        raise HTTPException(422, str(exc))
    session.commit()
    bus.publish("alerts", "incidents")
    return _detail(repo, row)


@router.patch("/{alert_id}/triage")
def triage_alert(alert_id: int, body: AlertTriage, session: Session = Depends(get_session)):
    """Set who is working on an alert and/or its tags. A field that is left out is not changed."""
    repo = AlertRepository(session)
    row = repo.get(alert_id)
    if row is None:
        raise HTTPException(404, "Alert not found")
    fields = body.model_dump(exclude_unset=True)
    try:
        triage.update(session, row, repo, assignee=fields.get("assignee", ...), tags=fields.get("tags", ...))
    except triage.TriageError as exc:
        raise HTTPException(422, str(exc)) from exc
    session.commit()
    bus.publish("alerts")
    return _detail(repo, row)
