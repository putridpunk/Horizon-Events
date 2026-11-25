"""Data housekeeping: retention of old events, and backup and restore of the built-in database."""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.data.service import DataError, DataService

router = APIRouter(prefix="/api/data", tags=["data"])


class RetentionUpdate(BaseModel):
    days: int


class PathBody(BaseModel):
    path: str


def _service(request: Request) -> DataService:
    service = getattr(request.app.state, "data", None)
    if service is None:
        raise HTTPException(409, "Data tools are not available.")
    return service


def _call(fn, *args):
    try:
        return fn(*args)
    except DataError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/status")
def status(request: Request):
    return _service(request).status()


@router.put("/retention")
def set_retention(body: RetentionUpdate, request: Request):
    service = _service(request)
    _call(service.set_retention, body.days)
    return service.status()


@router.post("/purge")
def purge(request: Request):
    service = _service(request)
    removed = service.purge()
    return {"removed": removed, **service.status()}


@router.post("/backup")
def backup(body: PathBody, request: Request):
    return _call(_service(request).backup, body.path)


@router.post("/restore")
def restore(body: PathBody, request: Request):
    return _call(_service(request).stage_restore, body.path)


@router.delete("/restore")
def cancel_restore(request: Request):
    _service(request).cancel_restore()
    return {"restore_pending": False}
