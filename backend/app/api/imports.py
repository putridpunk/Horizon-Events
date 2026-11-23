from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.collectors.base import SOURCE_TYPES
from app.config import get_settings
from app.database.connection import get_session
from app.services.ingestion import import_logs

router = APIRouter(prefix="/api/imports", tags=["imports"])


@router.post("")
async def create_import(file: UploadFile = File(...), source_type: str = Form(...),
                        session: Session = Depends(get_session)):
    if source_type not in SOURCE_TYPES:
        raise HTTPException(422, f"source_type must be one of: {', '.join(SOURCE_TYPES)}")
    limit = get_settings().max_upload_bytes
    content = await file.read(limit + 1)
    if len(content) > limit:
        raise HTTPException(413, f"File exceeds the {limit // (1024 * 1024)} MB upload limit")
    return import_logs(session, source_type, file.filename or "upload", content)
