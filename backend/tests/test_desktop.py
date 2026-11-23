import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

from app.desktop import SingleInstance, make_secret, pick_free_port, wait_until_ready
from app.main import app

SECRET = "s3cret-value-for-tests"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("HORIZON_SESSION_SECRET", SECRET)
    return TestClient(app, follow_redirects=False)


def test_guard_disabled_without_secret(monkeypatch):
    monkeypatch.delenv("HORIZON_SESSION_SECRET", raising=False)
    assert TestClient(app).get("/api/health").status_code == 200


def test_bootstrap_sets_cookie_and_redirects_without_the_secret_in_the_url(client):
    r = client.get(f"/api/health?hz={SECRET}&keep=1")
    assert r.status_code == 302
    assert r.headers["location"] == "/api/health?keep=1"
    assert SECRET not in r.headers["location"]
    assert f"hz_session={SECRET}" in r.headers["set-cookie"]


def test_bootstrap_on_the_root_redirects_to_a_clean_root(client):
    r = client.get(f"/?hz={SECRET}")
    assert (r.status_code, r.headers["location"]) == (302, "/")


def test_cookie_flags(client):
    cookie = client.get(f"/?hz={SECRET}").headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/" in cookie


def test_wrong_bootstrap_secret_is_401(client):
    r = client.get("/?hz=not-the-secret")
    assert r.status_code == 401 and "set-cookie" not in r.headers and SECRET not in r.text


@pytest.mark.parametrize("path", ["/", "/api/health", "/api/events", "/assets/anything.js", "/alerts"])
def test_missing_cookie_is_401_for_api_static_and_pages(client, path):
    assert client.get(path).status_code == 401


def test_wrong_cookie_is_401(client):
    client.cookies.set("hz_session", "wrong")
    assert client.get("/api/health").status_code == 401


def test_non_ascii_cookie_is_401_not_a_crash(client):
    r = client.get("/api/health", headers={"Cookie": "hz_session=café".encode("utf-8")})  # raw bytes, as a browser could send
    assert r.status_code == 401


def test_valid_cookie_reaches_the_api(client):
    client.cookies.set("hz_session", SECRET)
    assert client.get("/api/health").json() == {"status": "ok"}


def test_state_changing_requests_also_need_the_cookie(client):
    assert client.post("/api/watcher/pause").status_code == 401
    client.cookies.set("hz_session", SECRET)
    assert client.post("/api/watcher/pause").status_code == 409  # past the guard; watcher not enabled


def test_pick_free_port_is_bindable():
    port = pick_free_port()
    with socket.socket() as s:
        s.bind(("127.0.0.1", port))


def test_secret_is_long_and_unique():
    a, b = make_secret(), make_secret()
    assert a != b and len(a) >= 32


def test_single_instance_second_acquire_fails_until_release(tmp_path):
    first, second = SingleInstance(tmp_path / "app.lock"), SingleInstance(tmp_path / "app.lock")
    assert first.acquire() is True
    assert second.acquire() is False
    first.release()
    assert second.acquire() is True
    second.release()


def test_single_instance_release_twice_is_harmless(tmp_path):
    lock = SingleInstance(tmp_path / "x.lock")
    lock.acquire()
    lock.release()
    lock.release()


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(401)  # any HTTP answer, even 401, means the server is up
        self.end_headers()

    def log_message(self, *args):
        pass


def test_wait_until_ready_succeeds_and_times_out():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        assert wait_until_ready(f"http://127.0.0.1:{server.server_port}/", timeout=3) is True
    finally:
        server.shutdown()
    free = pick_free_port()
    assert wait_until_ready(f"http://127.0.0.1:{free}/", timeout=0.6) is False
