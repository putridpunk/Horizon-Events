from fastapi import APIRouter

from app.mitre import all_techniques

router = APIRouter(prefix="/api/mitre", tags=["mitre"])


@router.get("/techniques")
def techniques():
    return all_techniques()
