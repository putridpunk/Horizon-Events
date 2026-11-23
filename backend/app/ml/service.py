"""Training and status operations used by the API, the CLI and start-up code."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import EventRow
from app.database.repositories import row_to_event
from app.ml import model as ml
from app.ml.baseline import synthetic_baseline
from app.ml.features import FEATURE_NAMES


def status() -> dict:
    bundle = ml.load()
    if bundle is None:
        return {"trained": False, "trained_at": None, "windows": 0, "source": None, "features": FEATURE_NAMES}
    return {"trained": True, "trained_at": bundle.trained_at, "windows": bundle.n_windows,
            "source": bundle.source, "features": FEATURE_NAMES}


def train_from_database(session: Session) -> ml.ModelBundle:
    """Train on every stored event that has a source IP. Raises InsufficientData."""
    rows = session.scalars(select(EventRow).where(EventRow.source_ip.is_not(None)))
    bundle = ml.train([row_to_event(r) for r in rows], "database")
    ml.save(bundle)
    return bundle


def train_synthetic() -> ml.ModelBundle:
    bundle = ml.train(synthetic_baseline(), "synthetic")
    ml.save(bundle)
    return bundle


def ensure_model() -> bool:
    """Train the synthetic demo baseline if no usable model exists. Returns True if it trained."""
    if ml.load() is not None:
        return False
    train_synthetic()
    return True
