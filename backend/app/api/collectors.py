import sys

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.collector_models import get_setting, set_setting
from app.database.connection import get_session
from app.system import access
from app.system.registry import platform_name

router = APIRouter(prefix="/api", tags=["collectors"])

SECURITY_COLLECTOR = "windows-security"


class CollectorUpdate(BaseModel):
    enabled: bool | None = None
    backfill_hours: int | None = Field(default=None, ge=0, le=168)


def _manager(request: Request):
    return getattr(request.app.state, "collectors", None)


def _require_manager(request: Request):
    manager = _manager(request)
    if manager is None:
        raise HTTPException(409, "System log collection is not enabled in this mode.")
    return manager


@router.get("/collectors")
def list_collectors(request: Request):
    manager = _manager(request)
    return {"enabled": manager is not None, "platform": platform_name(),
            "items": manager.status() if manager else []}


@router.patch("/collectors/{collector_id}")
def update_collector(collector_id: str, body: CollectorUpdate, request: Request):
    manager = _require_manager(request)
    if collector_id not in manager.collectors:
        raise HTTPException(404, "Unknown collector")
    if body.enabled is None and body.backfill_hours is None:
        return manager.check(collector_id)
    enabled = body.enabled if body.enabled is not None else {s["id"]: s["enabled"] for s in manager.status()}[collector_id]
    return manager.set_enabled(collector_id, enabled, body.backfill_hours or None)


@router.post("/collectors/{collector_id}/check")
def check_collector(collector_id: str, request: Request):
    manager = _require_manager(request)
    if collector_id not in manager.collectors:
        raise HTTPException(404, "Unknown collector")
    return manager.check(collector_id)


@router.post("/collectors/security/enable-access")
def enable_security_access(request: Request):
    """Ask Windows to add the current user to Event Log Readers. Windows shows its own permission prompt;
    nothing changes unless the user approves it."""
    manager = _require_manager(request)
    if sys.platform != "win32":
        raise HTTPException(409, "The Security log is a Windows feature.")
    sid = access.current_user_sid()
    if sid is None:
        raise HTTPException(422, "Could not determine your Windows account.")
    requested = access.request_elevation(access.enable_command(sid))
    entry = manager.check(SECURITY_COLLECTOR) if SECURITY_COLLECTOR in manager.collectors else None
    return {"requested": requested, "access": entry["access"] if entry else "unavailable"}


@router.get("/setup")
def get_setup(request: Request, session: Session = Depends(get_session)):
    return {"completed": get_setting(session, "setup_completed", "false") == "true",
            "system_logs_enabled": _manager(request) is not None, "platform": platform_name()}


@router.post("/setup/complete")
def complete_setup(request: Request, session: Session = Depends(get_session)):
    set_setting(session, "setup_completed", "true")
    session.commit()
    return get_setup(request, session)
