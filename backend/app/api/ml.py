from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.ml import service
from app.ml.model import InsufficientData

router = APIRouter(prefix="/api/ml", tags=["ml"])


class TrainRequest(BaseModel):
    source: Literal["database", "synthetic"] = "synthetic"


@router.get("/status")
def model_status():
    return service.status()


@router.post("/train")
def train_model(body: TrainRequest, session: Session = Depends(get_session)):
    try:
        if body.source == "synthetic":
            service.train_synthetic()
        else:
            service.train_from_database(session)
    except InsufficientData as exc:
        raise HTTPException(422, f"{exc} Try training on the synthetic baseline instead.")
    return service.status()
