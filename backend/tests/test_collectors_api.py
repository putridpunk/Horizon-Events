import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api import collectors as collectors_api
from app.database.connection import get_session
from app.main import app
from app.system.base import NEEDS_PERMISSION, READY, Collector
from app.system.manager import CollectorManager

SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"


class Fake(Collector):
    platform = "windows"

    def __init__(self, id_, access=READY):
        self.id, self.name, self.description, self._access = id_, id_.title(), f"fake {id_} source", access

    def access(self):
        return self._access

    def poll(self, session, setting):
        return 0


@pytest.fixture
def client(engine):
    factory = lambda: Session(engine, expire_on_commit=False)  # noqa: E731

    def override():
        with factory() as s:
            yield s

    app.dependency_overrides[get_session] = override
    app.state.collectors = CollectorManager(
        [Fake("windows-system"), Fake("windows-security", access=NEEDS_PERMISSION)], factory, access_ttl=0)
    yield TestClient(app)
    app.dependency_overrides.clear()
    app.state.collectors = None


def test_list_shows_every_collector_with_its_state(client):
    d = client.get("/api/collectors").json()
    assert d["enabled"] is True and d["platform"] in {"windows", "linux", "other"}
    assert {i["id"]: i["state"] for i in d["items"]} == {"windows-system": "off", "windows-security": "off"}
    assert {i["id"]: i["access"] for i in d["items"]} == {"windows-system": "ready", "windows-security": "needs_permission"}


def test_enable_with_backfill_and_disable(client):
    r = client.patch("/api/collectors/windows-system", json={"enabled": True, "backfill_hours": 24})
    assert r.status_code == 200 and r.json()["enabled"] is True and r.json()["state"] == "collecting"
    assert client.patch("/api/collectors/windows-system", json={"enabled": False}).json()["state"] == "off"


def test_security_stays_needs_permission_until_access_is_granted(client):
    r = client.patch("/api/collectors/windows-security", json={"enabled": True}).json()
    assert r["enabled"] is True and r["state"] == "needs_permission"


@pytest.mark.parametrize("body", [{"backfill_hours": -1}, {"backfill_hours": 169}, {"enabled": "maybe"}])
def test_invalid_updates_are_422(client, body):
    assert client.patch("/api/collectors/windows-system", json=body).status_code == 422


def test_unknown_collector_is_404(client):
    assert client.patch("/api/collectors/nope", json={"enabled": True}).status_code == 404
    assert client.post("/api/collectors/nope/check").status_code == 404


def test_check_re_reads_access(client):
    app.state.collectors.collectors["windows-security"]._access = READY
    assert client.post("/api/collectors/windows-security/check").json()["access"] == "ready"


def test_off_state_when_system_logs_are_not_enabled(client):
    app.state.collectors = None
    assert client.get("/api/collectors").json() == {"enabled": False, "platform": collectors_api.platform_name(), "items": []}
    assert client.patch("/api/collectors/windows-system", json={"enabled": True}).status_code == 409
    assert client.post("/api/collectors/security/enable-access").status_code == 409


def test_setup_flow(client):
    assert client.get("/api/setup").json() == {
        "completed": False, "system_logs_enabled": True, "platform": collectors_api.platform_name()}
    assert client.post("/api/setup/complete").json()["completed"] is True
    assert client.get("/api/setup").json()["completed"] is True


def test_setup_reports_system_logs_off_in_server_mode(client):
    app.state.collectors = None
    assert client.get("/api/setup").json()["system_logs_enabled"] is False


# -- the one-time Security access request: the elevation is injected, never real -------------
@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    calls = []
    monkeypatch.setattr(collectors_api.access, "current_user_sid", lambda: SID)
    monkeypatch.setattr(collectors_api.access, "request_elevation", lambda cmd: calls.append(cmd) or True)
    return calls


def test_enable_access_requests_the_permission_prompt_exactly_once(client, windows):
    r = client.post("/api/collectors/security/enable-access")
    assert r.status_code == 200 and r.json()["requested"] is True
    assert len(windows) == 1 and windows[0][-1] == f"Add-LocalGroupMember -SID S-1-5-32-573 -Member {SID}"
    assert r.json()["access"] == "needs_permission"  # until Windows applies it (sign-out and in)


def test_enable_access_reports_a_declined_prompt(client, windows, monkeypatch):
    monkeypatch.setattr(collectors_api.access, "request_elevation", lambda cmd: False)
    r = client.post("/api/collectors/security/enable-access")
    assert r.status_code == 200 and r.json()["requested"] is False


def test_enable_access_without_a_known_account_is_422(client, windows, monkeypatch):
    monkeypatch.setattr(collectors_api.access, "current_user_sid", lambda: None)
    assert client.post("/api/collectors/security/enable-access").status_code == 422
    assert windows == []


def test_enable_access_is_not_available_off_windows(client, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    assert client.post("/api/collectors/security/enable-access").status_code == 409


def test_a_cross_site_page_cannot_trigger_the_permission_prompt(client, windows):
    r = client.post("/api/collectors/security/enable-access", headers={"Origin": "https://evil.example"})
    assert r.status_code == 403 and windows == []
