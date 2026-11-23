from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.database.incident_repository import IncidentRepository
from app.database.repositories import AlertRepository
from app.incidents.manager import IncidentManager
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


def upload(client, name="linux_auth.log", stype="linux_auth"):
    return client.post("/api/imports", files={"file": (name, (SAMPLES / name).read_bytes())},
                       data={"source_type": stype})


def incident_list(client, **params):
    return client.get("/api/incidents", params={"limit": 100, **params}).json()


def brute_force_incident(client):
    """The incident holding the HZ-001 alert for 192.168.1.15."""
    for item in incident_list(client)["items"]:
        detail = client.get(f"/api/incidents/{item['id']}").json()
        if any(a["rule_id"] == "HZ-001" for a in detail["alerts"]):
            return detail
    raise AssertionError("no incident with the HZ-001 alert")


def test_import_creates_incidents_fewer_than_alerts(client):
    upload(client)
    alerts = client.get("/api/alerts", params={"limit": 100}).json()["total"]
    incidents = incident_list(client)
    assert 0 < incidents["total"] < alerts
    detail = brute_force_incident(client)
    assert {"HZ-001", "HZ-006"} <= {a["rule_id"] for a in detail["alerts"]}  # same IP and the locked account


def test_reimport_creates_no_new_incidents(client):
    upload(client)
    before = incident_list(client)["total"]
    upload(client)
    assert incident_list(client)["total"] == before


def test_list_filters_and_order(client):
    upload(client)
    items = incident_list(client)["items"]
    assert items[0]["severity"] == "critical" and items[0]["incident_id"].startswith("INC-")
    assert incident_list(client, status="RESOLVED")["total"] == 0
    assert incident_list(client, severity="critical")["total"] >= 1


def test_detail_includes_alerts_history_techniques(client):
    upload(client)
    d = brute_force_incident(client)
    assert d["history"][0]["action"] == "created" and "192.168.1.15" in d["ips"] and "admin" in d["accounts"]
    assert "T1110" in {t["id"] for t in d["techniques"]} and d["first_activity"]
    assert all("intel" in a for a in d["alerts"])


def test_patch_status_title_and_note(client):
    upload(client)
    inc = brute_force_incident(client)
    r = client.patch(f"/api/incidents/{inc['id']}",
                     json={"status": "INVESTIGATING", "note": "checking", "title": "SSH brute force"})
    assert r.status_code == 200 and r.json()["status"] == "INVESTIGATING" and r.json()["title"] == "SSH brute force"
    actions = [(h["action"], h["detail"]) for h in r.json()["history"]]
    assert ("status_changed", "checking") in actions and any(a == "title_changed" for a, _ in actions)
    r = client.post(f"/api/incidents/{inc['id']}/notes", json={"text": "called the owner"})
    assert r.json()["history"][-1]["detail"] == "called the owner"
    assert client.post(f"/api/incidents/{inc['id']}/notes", json={"text": "  "}).status_code == 422


def test_patch_invalid_inputs_422_and_history_unchanged(client):
    upload(client)
    inc = brute_force_incident(client)
    url = f"/api/incidents/{inc['id']}"
    assert client.patch(url, json={"status": "OPEN", "title": "x"}).status_code == 422  # same-state jump
    assert client.patch(url, json={"status": "BOGUS"}).status_code == 422
    assert client.patch(url, json={"title": "  "}).status_code == 422
    after = client.get(url).json()
    assert len(after["history"]) == len(inc["history"]) and after["title"] == inc["title"]


def test_add_and_remove_alert(client):
    upload(client)
    items = incident_list(client)["items"]
    a, b = client.get(f"/api/incidents/{items[0]['id']}").json(), client.get(f"/api/incidents/{items[1]['id']}").json()
    moving = b["alerts"][0]["id"]
    r = client.post(f"/api/incidents/{a['id']}/alerts", json={"alert_id": moving})
    assert r.status_code == 200 and moving in {x["id"] for x in r.json()["alerts"]}
    assert client.post(f"/api/incidents/{a['id']}/alerts", json={"alert_id": 99999}).status_code == 404
    r = client.delete(f"/api/incidents/{a['id']}/alerts/{moving}")
    assert r.status_code == 200 and moving not in {x["id"] for x in r.json()["alerts"]}
    assert client.delete(f"/api/incidents/{a['id']}/alerts/{moving}").status_code == 404


def test_merge_endpoint_and_errors(client):
    upload(client)
    items = incident_list(client)["items"]
    a, b = items[0]["id"], items[1]["id"]
    assert client.post(f"/api/incidents/{a}/merge", json={"into": a}).status_code == 422
    assert client.post(f"/api/incidents/{a}/merge", json={"into": 99999}).status_code == 404
    r = client.post(f"/api/incidents/{a}/merge", json={"into": b})
    assert r.status_code == 200 and r.json()["alert_count"] >= 2
    assert client.get(f"/api/incidents/{a}").json()["status"] == "RESOLVED"


def test_missing_incident_404_and_empty_db(client):
    assert client.get("/api/incidents/999").status_code == 404
    assert client.patch("/api/incidents/999", json={"status": "RESOLVED"}).status_code == 404
    assert incident_list(client) == {"items": [], "total": 0}


def test_report_includes_incidents(client):
    upload(client)
    inc = client.get("/api/reports", params={"format": "json"}).json()["incidents"]
    assert inc["total"] >= 1 and inc["by_status"]["OPEN"] == inc["total"]
    assert "incident_status,OPEN" in client.get("/api/reports", params={"format": "csv"}).text
    assert "incidents" in client.get("/api/reports", params={"format": "html"}).text


def test_startup_backfill_groups_existing_alerts(client, engine):
    with Session(engine, expire_on_commit=False) as s:
        repo = AlertRepository(s)
        for i, ip in enumerate(("5.5.5.5", "5.5.5.5", "6.6.6.6")):
            repo.create(rule_id="HZ-001", rule_name="Repeated login failures", severity="high", status="OPEN",
                        key=f"k{i}", source_ip=ip, last_seen=datetime(2026, 11, 23, 10, i))
        s.commit()
        assert IncidentManager(IncidentRepository(s)).backfill() == 3
        s.commit()
    assert incident_list(client)["total"] == 2
