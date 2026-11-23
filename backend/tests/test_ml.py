from datetime import datetime

import pytest

from app.domain import EventType
from app.ml import model as ml
from app.ml.baseline import synthetic_baseline
from app.ml.features import FEATURE_NAMES, group_windows, window_features
from tests.conftest import make_event

SPRAY = [3.0, 3.0, 0.0, 3.0, 3.0, 1.0, 0.0]  # three failures, three failed users, working hours
TYPICAL = [2.0, 0.0, 2.0, 1.0, 0.0, 0.0, 0.0]


@pytest.fixture(scope="module")
def bundle():
    return ml.train(synthetic_baseline(), "synthetic")


def test_window_features_values():
    evs = [make_event(ts="2026-11-23T10:05:00", user=u) for u in ("a", "b", "c")]
    evs.append(make_event(EventType.authentication_success, ts="2026-11-23T10:30:00", user="a", raw="s"))
    assert window_features(evs) == [4.0, 3.0, 1.0, 3.0, 3.0, 0.75, 0.0]
    assert len(FEATURE_NAMES) == 7


def test_group_windows_ignores_events_without_ip():
    evs = [make_event(ip=None), make_event(ip="1.1.1.1"), make_event(ip="1.1.1.1", ts="2026-11-23T11:00:00")]
    w = group_windows(evs)
    assert set(w) == {("1.1.1.1", datetime(2026, 11, 23, 10)), ("1.1.1.1", datetime(2026, 11, 23, 11))}


def test_synthetic_baseline_is_deterministic():
    a, b = synthetic_baseline(), synthetic_baseline()
    assert [e.fingerprint() for e in a] == [e.fingerprint() for e in b]
    assert len(group_windows(a)) > 50


def test_train_raises_insufficient_data():
    with pytest.raises(ml.InsufficientData):
        ml.train([make_event()] * 10, "database")


def test_spray_window_is_outlier_and_typical_is_not(bundle):
    assert ml.score(bundle, SPRAY)[0] is True
    assert ml.score(bundle, TYPICAL)[0] is False


def test_explain_names_top_features(bundle):
    text = " ".join(ml.explain(bundle, SPRAY))
    assert "failures" in text and "distinct_failed_users" in text


def test_load_returns_none_for_missing_and_corrupt(tmp_path):
    assert ml.load(tmp_path / "missing.joblib") is None
    bad = tmp_path / "bad.joblib"
    bad.write_bytes(b"not a model")
    assert ml.load(bad) is None


def test_save_load_roundtrip(bundle, tmp_path):
    p = ml.save(bundle, tmp_path / "m.joblib")
    loaded = ml.load(p)
    assert loaded.n_windows == bundle.n_windows and ml.score(loaded, SPRAY)[0] is True
