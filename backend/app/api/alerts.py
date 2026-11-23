from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.alerts.manager import AlertManager, InvalidTransition
from app.api.schemas import AlertUpdate, alert_out, event_out, history_out
from app.database.connection import get_session
from app.database.repositories import AlertRepository

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


def _detail(repo: AlertRepository, row) -> dict:
    return {**alert_out(row), "events": [event_out(e) for e in repo.linked_events(row.id)],
            "history": [history_out(h) for h in repo.history(row.id)]}


@router.get("")
def list_alerts(severity: str | None = None, status: str | None = None, rule_id: str | None = None,
                limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
                session: Session = Depends(get_session)):
    rows, total = AlertRepository(session).list(severity, status, rule_id, limit, offset)
    return {"items": [alert_out(r) for r in rows], "total": total}


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
    return _detail(repo, row)
