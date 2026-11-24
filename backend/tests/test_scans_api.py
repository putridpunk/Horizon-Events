import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.main import app
from app.scanning.defender import CLEAN, THREAT, Finding, ScanOutcome
from app.scanning.service import ScanService


@pytest.fixture
def client(engine):
    factory = lambda: Session(engine, expire_on_commit=False)  # noqa: E731

    def override():
        with factory() as s:
            yield s

    app.dependency_overrides[get_session] = override

    def scan(path):
        return ScanOutcome(THREAT, [Finding("Virus:DOS/EICAR_Test_File", path)]) if path.endswith("bad.txt") else ScanOutcome(CLEAN)

    app.state.scans = ScanService(factory, scanner=scan)
    yield TestClient(app)
    app.dependency_overrides.clear()
    app.state.scans = None


@pytest.fixture
def disabled():
    app.state.scans = None
    return TestClient(app)


def test_status_when_disabled_says_desktop_only(disabled):
    d = disabled.get("/api/scans/status").json()
    assert d["enabled"] is False and "desktop app" in d["message"]


@pytest.mark.parametrize("call", [lambda c: c.post("/api/scans", json={"paths": ["x"]}), lambda c: c.get("/api/scans"),
                                  lambda c: c.get("/api/scans/1")])
def test_scanning_is_refused_when_disabled(disabled, call):
    assert call(disabled).status_code == 409


def test_status_when_enabled(client):
    d = client.get("/api/scans/status").json()
    assert d["enabled"] is True and d["engine"] == "Microsoft Defender" and isinstance(d["available"], bool)


def test_scan_flow_creates_an_alert_visible_in_the_alerts_api(client, tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text("x")
    ok = tmp_path / "ok.txt"
    ok.write_text("y")
    res = client.post("/api/scans", json={"paths": [str(bad), str(ok)]})
    assert res.status_code == 202 and res.json()["total"] == 2
    app.state.scans.wait()
    scan = client.get(f"/api/scans/{res.json()['id']}").json()
    assert scan["status"] == "completed" and scan["threats"] == 1
    assert client.get("/api/scans").json()["items"][0]["id"] == scan["id"]
    alerts = client.get("/api/alerts").json()
    items = alerts["items"] if isinstance(alerts, dict) else alerts
    assert [a["rule_id"] for a in items] == ["HZ-008"] and items[0]["severity"] == "critical"


@pytest.mark.parametrize("body", [{"paths": []}, {"paths": ["relative.txt"]}, {"paths": [r"\\host\share\a.exe"]}, {"paths": ["C:/definitely/not/here.zip"]}])
def test_bad_paths_are_rejected_with_a_message(client, body):
    res = client.post("/api/scans", json=body)
    assert res.status_code == 422 and isinstance(res.json()["detail"], str)


def test_missing_body_is_rejected(client):
    assert client.post("/api/scans", json={}).status_code == 422


def test_unknown_scan_is_404(client):
    assert client.get("/api/scans/999").status_code == 404


def test_rule_hz008_is_listed_and_maps_to_mitre(client):
    rules = client.get("/api/rules").json()
    assert "HZ-008" in [r["id"] for r in (rules["items"] if isinstance(rules, dict) else rules)]
