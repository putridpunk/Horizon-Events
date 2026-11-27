"""Status of the optional network syslog receiver."""
from fastapi import APIRouter, Request

router = APIRouter(prefix="/api/syslog", tags=["syslog"])


@router.get("/status")
def status(request: Request):
    receiver = getattr(request.app.state, "syslog", None)
    return receiver.status() if receiver else {"enabled": False}
