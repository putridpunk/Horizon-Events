from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.intel import service as intel
from app.main import app

SAMPLES = Path(__file__).resolve().parents[2] / "sample_logs"


@pytest.fixture
def client(engine):
    def override():
        with Session(engine, expire_on_commit=False) as s:
            yield s
    app.dependency_overrides[get_session] = override
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def demo(engine):
    with Session(engine) as s:
        intel.ensure_demo_feed(s)


def upload(client, name="linux_auth.log", stype="linux_auth"):
    return client.post("/api/imports", files={"file": (name, (SAMPLES / name).read_bytes())},
                       data={"source_type": stype})


def alert_for(client, ip):
    return next(a for a in client.get("/api/alerts", params={"limit": 100}).json()["items"] if a["source_ip"] == ip)


def test_alert_includes_intel_for_demo_ip(client, demo):
    upload(client)
    a = alert_for(client, "203.0.113.7")
    assert a["intel"]["listed"] is True and "Synthetic" in a["intel"]["feeds"][0]["name"]
    assert client.get(f"/api/alerts/{a['id']}").json()["intel"]["listed"] is True


def test_alert_without_listed_ip_not_listed(client, demo):
    upload(client)
    assert alert_for(client, "192.168.1.15")["intel"] == {"listed": False, "feeds": []}


def test_alerts_without_ip_are_not_listed(client, demo):
    upload(client)
    no_ip = [a for a in client.get("/api/alerts", params={"limit": 100}).json()["items"] if a["source_ip"] is None]
    assert no_ip and all(a["intel"]["listed"] is False for a in no_ip)


def test_event_detail_includes_intel(client, demo):
    upload(client)
    ev = client.get("/api/events", params={"q": "203.0.113.7"}).json()["items"][0]
    assert client.get(f"/api/events/{ev['id']}").json()["intel"]["listed"] is True


def test_status_endpoint(client, demo):
    d = client.get("/api/intel/status").json()
    assert d["min_refresh_minutes"] == 60 and d["feeds"][0]["id"] == "demo"


def test_refresh_endpoint_with_fake_fetch(client, monkeypatch):
    monkeypatch.setattr(intel, "http_fetch", lambda url: "203.0.113.200\n")
    r = client.post("/api/intel/refresh", json={"feeds": ["feodo"]}).json()
    assert r["results"][0]["status"] == "updated"
    assert {f["id"] for f in r["feeds"]} == {"feodo"}
    again = client.post("/api/intel/refresh", json={"feeds": ["feodo"]}).json()
    assert again["results"][0]["status"] == "too_soon"


def test_refresh_unknown_feed_422(client):
    assert client.post("/api/intel/refresh", json={"feeds": ["nope"]}).status_code == 422


def test_report_counts_intel_matches(client, demo):
    upload(client)
    assert client.get("/api/reports", params={"format": "json"}).json()["intel_matches"] >= 1
    assert "alerts_with_known_malicious_ip" in client.get("/api/reports", params={"format": "csv"}).text
    assert "threat feed" in client.get("/api/reports", params={"format": "html"}).text
