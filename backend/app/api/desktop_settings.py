"""How the desktop app behaves around its window: tray, notifications and starting with Windows."""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.shell.settings import ShellError, ShellSettings

router = APIRouter(prefix="/api/desktop", tags=["desktop"])


class DesktopUpdate(BaseModel):
    run_in_background: bool | None = None
    notify: str | None = None
    start_with_windows: bool | None = None


def _service(request: Request) -> ShellSettings | None:
    return getattr(request.app.state, "shell", None)


@router.get("/settings")
def get_settings_(request: Request):
    service = _service(request)
    if service is None:
        return {"enabled": False}
    return {"enabled": True, **service.get()}


@router.put("/settings")
def put_settings(body: DesktopUpdate, request: Request):
    service = _service(request)
    if service is None:
        raise HTTPException(409, "These settings are only available in the desktop app.")
    try:
        return {"enabled": True, **service.update(body.run_in_background, body.notify, body.start_with_windows)}
    except ShellError as exc:
        raise HTTPException(422, str(exc)) from exc
