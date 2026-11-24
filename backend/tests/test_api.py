from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.config import Settings
from app.database.connection import get_session
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


def upload(client, name, stype):
    data = (SAMPLES / name).read_bytes()
    return client.post("/api/imports", files={"file": (name, data)}, data={"source_type": stype})


def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok"}


def test_import_then_list_events(client):
    r = upload(client, "linux_auth.log", "linux_auth")
    assert r.status_code == 200 and r.json()["imported"] > 10 and r.json()["skipped"] == 1
    ev = client.get("/api/events", params={"severity": "medium", "limit": 5}).json()
    assert len(ev["items"]) == 5 and ev["total"] >= 16
    one = client.get(f"/api/events/{ev['items'][0]['id']}").json()
    assert one["raw"] and client.get("/api/events/99999").status_code == 404


def test_import_oversize_413(client, monkeypatch):
    monkeypatch.setattr("app.api.imports.get_settings", lambda: Settings(max_upload_bytes=10))
    r = client.post("/api/imports", files={"file": ("x.log", b"a" * 50)}, data={"source_type": "linux_auth"})
    assert r.status_code == 413


def test_import_bad_source_422(client):
    r = client.post("/api/imports", files={"file": ("x.log", b"a")}, data={"source_type": "nope"})
    assert r.status_code == 422


def test_alert_detail_and_status_workflow(client):
    upload(client, "linux_auth.log", "linux_auth")
    alerts = client.get("/api/alerts").json()["items"]
    assert alerts[0]["severity"] == "critical" and alerts[0]["alert_id"].startswith("ALT-")
    aid = alerts[0]["id"]
    detail = client.get(f"/api/alerts/{aid}").json()
    assert len(detail["events"]) == detail["occurrences"] and detail["history"][0]["to_status"] == "OPEN"
    r = client.patch(f"/api/alerts/{aid}", json={"status": "INVESTIGATING", "note": "checking"})
    assert r.status_code == 200 and r.json()["history"][-1]["note"] == "checking"
    assert client.get("/api/alerts", params={"status": "INVESTIGATING"}).json()["total"] == 1


def test_patch_alert_invalid_status_422(client):
    upload(client, "linux_auth.log", "linux_auth")
    aid = client.get("/api/alerts").json()["items"][0]["id"]
    assert client.patch(f"/api/alerts/{aid}", json={"status": "BOGUS"}).status_code == 422
    assert client.patch(f"/api/alerts/{aid}", json={"status": "OPEN"}).status_code == 422  # same-state jump
    assert len(client.get(f"/api/alerts/{aid}").json()["history"]) == 1
    assert client.patch("/api/alerts/9999", json={"status": "RESOLVED"}).status_code == 404


def test_patch_rule_threshold_changes_detection(client):
    client.get("/api/rules")
    r = client.patch("/api/rules/HZ-001", json={"params": {"threshold": 50, "critical_threshold": 60}})
    assert r.json()["params"]["threshold"] == 50 and r.json()["params"]["window_minutes"] == 5
    upload(client, "linux_auth.log", "linux_auth")
    assert client.get("/api/alerts", params={"rule_id": "HZ-001"}).json()["total"] == 0
    assert client.patch("/api/rules/HZ-XXX", json={}).status_code == 404


def test_disabled_rule_does_not_fire(client):
    client.get("/api/rules")
    client.patch("/api/rules/HZ-006", json={"enabled": False})
    upload(client, "linux_auth.log", "linux_auth")
    assert client.get("/api/alerts", params={"rule_id": "HZ-006"}).json()["total"] == 0


def test_statistics_empty_db(client):
    assert client.get("/api/statistics/overview").json()["total_events"] == 0
    for path in ("timeseries", "event-types", "source-ips", "rules"):
        assert client.get(f"/api/statistics/{path}").status_code == 200
    assert client.get("/api/statistics/timeseries", params={"bucket": "x"}).status_code == 422


def test_statistics_after_import(client):
    upload(client, "linux_auth.log", "linux_auth")
    assert client.get("/api/statistics/overview").json()["critical_alerts"] >= 1
    assert client.get("/api/statistics/source-ips").json()[0]["name"] == "192.168.1.15"


def test_report_formats(client):
    upload(client, "linux_auth.log", "linux_auth")
    for fmt, ctype in (("json", "application/json"), ("csv", "text/csv"), ("html", "text/html")):
        r = client.get("/api/reports", params={"format": fmt})
        assert r.status_code == 200 and r.headers["content-type"].startswith(ctype)
    assert client.get("/api/reports", params={"format": "pdf"}).status_code == 422
    assert client.get("/api/reports", params={"start": "2026-12-01", "end": "2026-11-01"}).status_code == 422


def test_alert_includes_techniques(client):
    upload(client, "linux_auth.log", "linux_auth")
    hz1 = client.get("/api/alerts", params={"rule_id": "HZ-001"}).json()["items"][0]
    assert "T1110" in {t["id"] for t in hz1["techniques"]}
    detail = client.get(f"/api/alerts/{hz1['id']}").json()
    assert detail["techniques"][0]["url"].startswith("https://attack.mitre.org/techniques/")


def test_rules_include_techniques_and_mitre_endpoint(client):
    rules = client.get("/api/rules").json()
    assert all(r["techniques"] for r in rules)
    ids = {t["id"] for t in client.get("/api/mitre/techniques").json()}
    assert {"T1110", "T1110.003", "T1489"} <= ids


def test_statistics_mitre_empty_db(client):
    d = client.get("/api/statistics/mitre").json()
    assert len(d["tactics"]) == 8 and all(t["alerts"] == 0 for t in d["tactics"])
    assert all(t["alerts"] == 0 for t in d["techniques"])


def test_statistics_mitre_after_import(client):
    upload(client, "linux_auth.log", "linux_auth")
    tactics = {t["tactic"]: t["alerts"] for t in client.get("/api/statistics/mitre").json()["tactics"]}
    assert tactics["Credential Access"] >= 1


def test_report_includes_techniques(client):
    upload(client, "linux_auth.log", "linux_auth")
    assert any(t["alerts"] for t in client.get("/api/reports", params={"format": "json"}).json()["techniques"])
    assert "technique," in client.get("/api/reports", params={"format": "csv"}).text
    assert "MITRE ATT&amp;CK" in client.get("/api/reports", params={"format": "html"}).text


def test_report_html_escapes_technique_names(client, monkeypatch):
    import app.mitre as mitre
    monkeypatch.setitem(mitre.TECHNIQUES, "T1110", ("<script>x</script>", ("Credential Access",)))
    upload(client, "linux_auth.log", "linux_auth")
    html = client.get("/api/reports", params={"format": "html"}).text
    assert "<script>x</script>" not in html and "&lt;script&gt;x&lt;/script&gt;" in html
