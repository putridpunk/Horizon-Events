from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.reports.generator import FORMATS, build_report, render

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("")
def get_report(start: datetime = datetime(1970, 1, 1), end: datetime = datetime(2100, 1, 1),
               format: str = "json", session: Session = Depends(get_session)):
    if format not in FORMATS:
        raise HTTPException(422, f"format must be one of: {', '.join(FORMATS)}")
    if end < start:
        raise HTTPException(422, "end must not be before start")
    body, media_type = render(build_report(session, start, end), format)
    return Response(body, media_type=media_type,
                    headers={"Content-Disposition": f'attachment; filename="horizon-report.{format}"'})
