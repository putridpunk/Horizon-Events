"""Recommended steps for alerts, and (in the desktop app) approving, dismissing and undoing mitigations."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.database.repositories import AlertRepository
from app.mitigation.advice import advice_for
from app.mitigation.service import MitigationError, MitigationService, load_settings, save_settings

router = APIRouter(prefix="/api/mitigation", tags=["mitigation"])

DESKTOP_ONLY = "Carrying out actions is only available in the desktop app."


class SettingsUpdate(BaseModel):
    block_ip: str | None = None
    quarantine_file: str | None = None
    block_private: bool | None = None
    block_days: int | None = None
    allowlist: list[str] | None = None


def _service(request: Request) -> MitigationService:
    service = getattr(request.app.state, "mitigation", None)
    if service is None:
        raise HTTPException(409, DESKTOP_ONLY)
    return service


def _settings_out(request: Request, session: Session) -> dict:
    return {"enabled": getattr(request.app.state, "mitigation", None) is not None, **load_settings(session)}


@router.get("/settings")
def get_settings_(request: Request, session: Session = Depends(get_session)):
    return _settings_out(request, session)


@router.put("/settings")
def put_settings(body: SettingsUpdate, request: Request, session: Session = Depends(get_session)):
    try:
        save_settings(session, body.model_dump(exclude_none=True))
    except MitigationError as exc:
        raise HTTPException(422, str(exc)) from exc
    session.commit()
    return _settings_out(request, session)


@router.get("/alerts/{alert_id}")
def for_alert(alert_id: int, request: Request, session: Session = Depends(get_session)):
    alert = AlertRepository(session).get(alert_id)
    if alert is None:
        raise HTTPException(404, "Alert not found")
    service = getattr(request.app.state, "mitigation", None)
    out = {"enabled": service is not None, "advice": advice_for(alert.rule_id), "actions": [], "skipped": []}
    if service is not None:
        out.update(service.for_alert(session, alert))
        session.commit()
    return out


@router.get("/history")
def history(request: Request):
    return {"items": _service(request).history()}


def _act(request: Request, mitigation_id: int, name: str) -> dict:
    try:
        return getattr(_service(request), name)(mitigation_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except MitigationError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/{mitigation_id}/approve")
def approve(mitigation_id: int, request: Request):
    return _act(request, mitigation_id, "approve")


@router.post("/{mitigation_id}/dismiss")
def dismiss(mitigation_id: int, request: Request):
    return _act(request, mitigation_id, "dismiss")


@router.post("/{mitigation_id}/undo")
def undo(mitigation_id: int, request: Request):
    return _act(request, mitigation_id, "undo")
