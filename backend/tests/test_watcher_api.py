import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.watcher.service import WatchService


@pytest.fixture
def client():
    yield TestClient(app)
    app.state.watcher = None


def test_status_disabled(client):
    app.state.watcher = None
    assert client.get("/api/watcher/status").json() == {"enabled": False}


def test_status_enabled_lists_files(client, engine, tmp_path):
    svc = WatchService(tmp_path / "watch", lambda: Session(engine, expire_on_commit=False))
    folder = tmp_path / "watch" / "linux_auth"
    folder.mkdir(parents=True)
    (folder / "a.log").write_text("Nov 23 14:20:31 s sshd[1]: Accepted password for a from 1.1.1.1 port 1\n")
    svc.scan_once()
    app.state.watcher = svc
    s = client.get("/api/watcher/status").json()
    assert s["enabled"] is True and s["files"][0]["path"] == "linux_auth/a.log" and s["total_imported"] == 1


def test_pause_resume(client, engine, tmp_path):
    app.state.watcher = WatchService(tmp_path / "w", lambda: Session(engine))
    assert client.post("/api/watcher/pause").json()["paused"] is True
    assert client.post("/api/watcher/resume").json()["paused"] is False


def test_pause_when_disabled_409(client):
    app.state.watcher = None
    assert client.post("/api/watcher/pause").status_code == 409
    assert client.post("/api/watcher/resume").status_code == 409
