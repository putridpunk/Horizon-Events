"""File scanning: start a scan of chosen files and folders, follow its progress, list recent scans."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_session

from app.scanning.downloads import DownloadsError, load_config, save_config
from app.scanning.service import ScanBusy, ScanService

router = APIRouter(prefix="/api/scans", tags=["scans"])


class ScanRequest(BaseModel):
    paths: list[str]


class DownloadsUpdate(BaseModel):
    enabled: bool | None = None
    folder: str | None = None


def _downloads_out(request: Request, session: Session) -> dict:
    watcher = getattr(request.app.state, "downloads", None)
    return {"available": watcher is not None, **load_config(session), **(watcher.status() if watcher else {})}


@router.get("/downloads")
def get_downloads(request: Request, session: Session = Depends(get_session)):
    return _downloads_out(request, session)


@router.put("/downloads")
def put_downloads(body: DownloadsUpdate, request: Request, session: Session = Depends(get_session)):
    if getattr(request.app.state, "downloads", None) is None:
        raise HTTPException(409, "File scanning is only available in the desktop app.")
    try:
        save_config(session, body.enabled, body.folder)
    except DownloadsError as exc:
        raise HTTPException(422, str(exc)) from exc
    session.commit()
    return _downloads_out(request, session)


def _service(request: Request) -> ScanService:
    service = getattr(request.app.state, "scans", None)
    if service is None:
        raise HTTPException(409, "File scanning is only available in the desktop app.")
    return service


@router.get("/status")
def status(request: Request):
    service = getattr(request.app.state, "scans", None)
    if service is None:
        return {"enabled": False, "engine": "Microsoft Defender", "available": False,
                "message": "File scanning is only available in the desktop app."}
    return service.engine_status()


@router.post("", status_code=202)
def start_scan(body: ScanRequest, request: Request):
    service = _service(request)
    try:
        return service.start(body.paths)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except ScanBusy as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("")
def recent_scans(request: Request):
    return {"items": _service(request).recent()}


@router.get("/{scan_id}")
def get_scan(scan_id: int, request: Request):
    scan = _service(request).get(scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    return scan
