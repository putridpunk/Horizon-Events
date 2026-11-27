"""Checking for a newer release of Horizon Events (it only tells; installing is the user's decision)."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.update import check as updates

router = APIRouter(prefix="/api/update", tags=["update"])


class UpdateSettings(BaseModel):
    auto_check: bool


@router.get("")
def get_status(session: Session = Depends(get_session)):
    return updates.status(session)


@router.post("/check")
def check_now(session: Session = Depends(get_session)):
    """Ask GitHub for the latest release now (the only network request this feature makes)."""
    return updates.check(session)


@router.put("/settings")
def set_settings(body: UpdateSettings, session: Session = Depends(get_session)):
    updates.set_auto(session, body.auto_check)
    session.commit()
    return updates.status(session)
