"""File scanning: start a scan of chosen files and folders, follow its progress, list recent scans."""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.scanning.service import ScanBusy, ScanService

router = APIRouter(prefix="/api/scans", tags=["scans"])


class ScanRequest(BaseModel):
    paths: list[str]


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
