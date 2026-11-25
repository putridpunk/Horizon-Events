"""Known false positives: list, add and remove suppressions, and suppress from an alert."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.alerts.manager import AlertManager, InvalidTransition
from app.alerts.suppression import SuppressionError, Suppressions
from app.database.connection import get_session
from app.database.repositories import AlertRepository
from app.domain import AlertStatus

router = APIRouter(prefix="/api", tags=["suppressions"])


class SuppressionCreate(BaseModel):
    rule_id: str | None = None
    source_ip: str | None = None
    username: str | None = None
    note: str = ""


@router.get("/suppressions")
def list_suppressions(session: Session = Depends(get_session)):
    return {"items": [r.as_dict() for r in Suppressions(session).list()]}


@router.post("/suppressions", status_code=201)
def create_suppression(body: SuppressionCreate, session: Session = Depends(get_session)):
    try:
        row = Suppressions(session).create(body.rule_id, body.source_ip, body.username, body.note)
    except SuppressionError as exc:
        raise HTTPException(422, str(exc)) from exc
    session.commit()
    return row.as_dict()


@router.delete("/suppressions/{suppression_id}")
def delete_suppression(suppression_id: int, session: Session = Depends(get_session)):
    if not Suppressions(session).delete(suppression_id):
        raise HTTPException(404, "Suppression not found")
    session.commit()
    return {"deleted": suppression_id}


@router.post("/alerts/{alert_id}/suppress", status_code=201)
def suppress_alert(alert_id: int, session: Session = Depends(get_session)):
    """Suppress future alerts like this one (same rule, address and account) and resolve this alert."""
    repo = AlertRepository(session)
    alert = repo.get(alert_id)
    if alert is None:
        raise HTTPException(404, "Alert not found")
    try:
        row = Suppressions(session).create(alert.rule_id, alert.source_ip, alert.username,
                                           f"Suppressed from {alert.rule_id} alert {alert.id}")
    except SuppressionError as exc:
        raise HTTPException(422, str(exc)) from exc
    if alert.status != AlertStatus.RESOLVED.value:
        try:
            AlertManager(repo).change_status(alert.id, AlertStatus.RESOLVED, "Suppressed as a known false positive")
        except InvalidTransition:
            pass
    session.commit()
    return row.as_dict()
