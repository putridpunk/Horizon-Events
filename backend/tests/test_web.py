import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.web import mount_frontend


@pytest.fixture
def client(tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "app.js").write_text("console.log(1)")
    (tmp_path / "index.html").write_text("<html>SPA</html>")
    api = FastAPI()

    @api.get("/api/ping")
    def ping():
        return {"ok": True}

    mount_frontend(api, tmp_path)
    return TestClient(api)


def test_api_routes_keep_priority(client):
    assert client.get("/api/ping").json() == {"ok": True}
    assert client.get("/api/missing").status_code == 404


def test_spa_fallback_and_assets(client):
    assert "SPA" in client.get("/alerts").text
    assert client.get("/assets/app.js").text == "console.log(1)"


def test_path_traversal_is_not_served(client):
    assert "SPA" in client.get("/..%2f..%2fetc/passwd").text


def test_missing_build_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        mount_frontend(FastAPI(), tmp_path)
