"""Protection for a service that listens on localhost: a malicious web page open in the user's browser
must not be able to drive it (cross-site requests) or read it (DNS rebinding)."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.database.repositories import EventRepository
from app.main import app
from app.watcher.service import WatchService

SAMPLES = Path(__file__).resolve().parents[2] / "sample_logs"
EVIL = {"Origin": "https://evil.example"}


@pytest.fixture
def client(engine):
    def override():
        with Session(engine, expire_on_commit=False) as s:
            yield s
    app.dependency_overrides[get_session] = override
    yield TestClient(app)
    app.dependency_overrides.clear()
    app.state.watcher = None


def event_count(engine):
    with Session(engine) as s:
        return EventRepository(s).search()[1]


def import_request(client, headers=None):
    data = (SAMPLES / "linux_auth.log").read_bytes()
    return client.post("/api/imports", files={"file": ("auth.log", data)}, data={"source_type": "linux_auth"},
                       headers=headers or {})


def test_cross_site_import_is_blocked_and_stores_nothing(client, engine):
    r = import_request(client, EVIL)  # a plain multipart form post needs no CORS preflight
    assert r.status_code == 403 and event_count(engine) == 0


def test_cross_site_watcher_pause_is_blocked(client, engine, tmp_path):
    app.state.watcher = WatchService(tmp_path / "w", lambda: Session(engine))
    assert client.post("/api/watcher/pause", headers=EVIL).status_code == 403
    assert app.state.watcher.status()["paused"] is False


@pytest.mark.parametrize("method,path", [("patch", "/api/rules/HZ-001"), ("delete", "/api/incidents/1/alerts/1"),
                                         ("post", "/api/intel/refresh"), ("post", "/api/ml/train")])
def test_every_state_changing_method_checks_the_origin(client, method, path):
    assert getattr(client, method)(path, headers=EVIL).status_code == 403


def test_opaque_null_origin_is_blocked(client):
    assert client.post("/api/watcher/pause", headers={"Origin": "null"}).status_code == 403


@pytest.mark.parametrize("origin", ["http://localhost:5173", "http://127.0.0.1:8000", "http://[::1]:8080",
                                    "http://localhost"])
def test_local_origins_are_allowed(client, origin):
    # the watcher is not enabled in this test, so a request that gets past the guard answers 409
    assert client.post("/api/watcher/pause", headers={"Origin": origin}).status_code == 409


def test_requests_without_an_origin_header_still_work(client, engine):
    assert import_request(client).status_code == 200 and event_count(engine) > 0  # curl, scripts, the exe's own UI


def test_reads_do_not_require_an_origin(client):
    assert client.get("/api/health", headers=EVIL).status_code == 200  # GET is not state-changing; CORS stops reading


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8000", "127.0.0.1.evil.example", "attacker.test"])
def test_unknown_host_header_is_rejected_to_stop_dns_rebinding(client, host):
    assert client.get("/api/health", headers={"Host": host}).status_code == 400
    assert client.get("/api/statistics/overview", headers={"Host": host}).status_code == 400


@pytest.mark.parametrize("host", ["localhost", "localhost:8080", "127.0.0.1:8000", "[::1]:8000", "LOCALHOST"])
def test_local_host_headers_are_accepted(client, host):
    assert client.get("/api/health", headers={"Host": host}).status_code == 200


def test_extra_hosts_can_be_allowed_through_configuration(client, monkeypatch):
    assert client.get("/api/health", headers={"Host": "siem.corp.example"}).status_code == 400
    monkeypatch.setenv("HORIZON_ALLOWED_HOSTS", "testserver, siem.corp.example")
    assert client.get("/api/health", headers={"Host": "siem.corp.example"}).status_code == 200
    assert client.post("/api/watcher/pause", headers={"Origin": "https://siem.corp.example"}).status_code == 409
