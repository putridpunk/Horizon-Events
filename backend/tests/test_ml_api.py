from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.main import app
from app.ml import service

SAMPLES = Path(__file__).resolve().parents[2] / "sample_logs"


@pytest.fixture
def client(engine, tmp_path, monkeypatch):
    monkeypatch.setenv("HORIZON_MODEL_PATH", str(tmp_path / "model.joblib"))

    def override():
        with Session(engine, expire_on_commit=False) as s:
            yield s
    app.dependency_overrides[get_session] = override
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_status_untrained(client):
    s = client.get("/api/ml/status").json()
    assert s["trained"] is False and s["windows"] == 0 and len(s["features"]) == 7


def test_train_synthetic_then_status_trained(client):
    r = client.post("/api/ml/train", json={"source": "synthetic"})
    assert r.status_code == 200 and r.json()["trained"] is True and r.json()["source"] == "synthetic"
    assert client.get("/api/ml/status").json()["windows"] > 50


def test_train_database_with_thin_data_422(client):
    r = client.post("/api/ml/train", json={"source": "database"})
    assert r.status_code == 422 and "synthetic" in r.json()["detail"]
    assert client.get("/api/ml/status").json()["trained"] is False


def test_train_unknown_source_422(client):
    assert client.post("/api/ml/train", json={"source": "bogus"}).status_code == 422


def test_end_to_end_spray_alert_via_api(client):
    client.post("/api/ml/train", json={"source": "synthetic"})
    data = (SAMPLES / "slow_spray.log").read_bytes()
    r = client.post("/api/imports", files={"file": ("slow_spray.log", data)}, data={"source_type": "linux_auth"})
    assert r.status_code == 200
    alerts = client.get("/api/alerts", params={"rule_id": "HZ-007"}).json()
    assert alerts["total"] == 1 and alerts["items"][0]["source_ip"] == "198.51.100.77"


def test_ensure_model_trains_only_when_missing(client):
    assert service.ensure_model() is True
    assert service.ensure_model() is False
