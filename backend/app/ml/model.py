"""Isolation Forest model bundle: training, scoring, explanation and persistence."""
from __future__ import annotations

import os
import statistics
from dataclasses import dataclass
from pathlib import Path

import joblib
from sklearn.ensemble import IsolationForest

from app.domain import Event, utcnow
from app.ml.features import FEATURE_NAMES, group_windows, window_features

MIN_WINDOWS = 50


class InsufficientData(ValueError):
    pass


@dataclass
class ModelBundle:
    model: IsolationForest
    means: list[float]
    stds: list[float]
    trained_at: str
    n_windows: int
    source: str
    high_cutoff: float


def model_path() -> Path:
    return Path(os.environ.get("HORIZON_MODEL_PATH", "horizon_model.joblib"))


def train(events: list[Event], source: str, contamination: float = 0.01) -> ModelBundle:
    vectors = [window_features(w) for w in group_windows(events).values()]
    if len(vectors) < MIN_WINDOWS:
        raise InsufficientData(
            f"Need at least {MIN_WINDOWS} per-IP hourly windows to train, found {len(vectors)}.")
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=42).fit(vectors)
    scores = sorted(model.score_samples(vectors))
    columns = list(zip(*vectors))
    return ModelBundle(
        model=model,
        means=[statistics.fmean(c) for c in columns],
        stds=[statistics.pstdev(c) for c in columns],
        trained_at=utcnow().isoformat(), n_windows=len(vectors), source=source,
        high_cutoff=scores[int(0.001 * len(scores))])


def score(bundle: ModelBundle, vector: list[float]) -> tuple[bool, float]:
    """Return (is_outlier, anomaly score); lower scores are more anomalous."""
    outlier = bundle.model.predict([vector])[0] == -1
    return bool(outlier), float(bundle.model.score_samples([vector])[0])


def is_high(bundle: ModelBundle, value: float) -> bool:
    return value <= bundle.high_cutoff


def explain(bundle: ModelBundle, vector: list[float], top: int = 3) -> list[str]:
    """Describe the features that deviate most (upwards) from the training baseline."""
    z = [(v - m) / max(s, 0.1) for v, m, s in zip(vector, bundle.means, bundle.stds)]
    order = sorted(range(len(z)), key=lambda i: z[i], reverse=True)
    return [f"{FEATURE_NAMES[i]} {vector[i]:g} (typical {bundle.means[i]:.1f})"
            for i in order[:top] if z[i] > 0]


_cache: dict[str, tuple[float, ModelBundle]] = {}


def save(bundle: ModelBundle, path: Path | None = None) -> Path:
    path = Path(path or model_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)
    _cache.pop(str(path), None)
    return path


def load(path: Path | None = None) -> ModelBundle | None:
    """Load the saved model, or None if it is missing or unreadable."""
    path = Path(path or model_path())
    try:
        mtime = path.stat().st_mtime
        cached = _cache.get(str(path))
        if cached and cached[0] == mtime:
            return cached[1]
        bundle = joblib.load(path)
        if not isinstance(bundle, ModelBundle):
            return None
        _cache[str(path)] = (mtime, bundle)
        return bundle
    except Exception:  # missing, corrupt or incompatible file: treat as untrained
        return None
