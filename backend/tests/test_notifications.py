import hashlib
import hmac
import json
import smtplib
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.database.notification_models import NotificationChannelRow
from app.main import app
from app.notifications import senders
from app.notifications.service import NotificationService, set_service
from app.notifications import service as service_module

SAMPLES = Path(__file__).resolve().parents[2] / "sample_logs"


class FakePost:
    def __init__(self, status=200, error=None):
        self.calls, self.status, self.error = [], status, error

    def __call__(self, url, body, headers, timeout):
        if self.error:
            raise senders.SendError(self.error)
        self.calls.append((url, json.loads(body), headers))
        return self.status


class FakeSmtp:
    sent: list = []

    def __init__(self, fail=False):
        self.fail, self.log = fail, []

    def __call__(self, host, port, security, timeout):
        self.log.append(("connect", host, port, security))
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        self.log.append(("starttls",))

    def login(self, user, password):
        self.log.append(("login", user, password))

    def send_message(self, msg):
        if self.fail:
            raise smtplib.SMTPAuthenticationError(535, b"bad credentials")
        self.log.append(("send", msg))


@pytest.fixture
def post():
    fake = FakePost()
    set_service(NotificationService(post=fake, smtp_factory=FakeSmtp()))
    yield fake
    set_service(NotificationService())


@pytest.fixture
def client(engine):
    def override():
        with Session(engine, expire_on_commit=False) as s:
            yield s
    app.dependency_overrides[get_session] = override
    yield TestClient(app)
    app.dependency_overrides.clear()


def make(client, **over):
    body = {"name": "Chat", "kind": "slack", "config": {"url": "https://hooks.slack.com/services/T/B/X"},
            "min_severity": "high", **over}
    r = client.post("/api/notifications", json=body)
    assert r.status_code == 201, r.text
    return r.json()


# ---- validation ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("kind,config", [
    ("slack", {"url": "http://hooks.slack.com/x"}),  # Slack and Discord must use https
    ("discord", {"url": "ftp://example.com"}), ("webhook", {"url": "javascript:alert(1)"}), ("webhook", {}),
    ("email", {"host": "", "from_addr": "a@b.c", "to_addrs": ["x@y.z"]}),
    ("email", {"host": "smtp.x", "from_addr": "nope", "to_addrs": ["x@y.z"]}),
    ("email", {"host": "smtp.x", "from_addr": "a@b.c", "to_addrs": []}),
    ("email", {"host": "smtp.x", "from_addr": "a@b.c", "to_addrs": ["bad address"]}),
    ("email", {"host": "smtp.x", "port": 99999, "from_addr": "a@b.c", "to_addrs": ["x@y.z"]}),
    ("email", {"host": "smtp.x", "security": "weird", "from_addr": "a@b.c", "to_addrs": ["x@y.z"]}),
    ("sms", {}),
])
def test_bad_channel_settings_are_refused(client, kind, config):
    r = client.post("/api/notifications", json={"name": "x", "kind": kind, "config": config})
    assert r.status_code == 422


def test_header_injection_in_email_addresses_is_refused():
    with pytest.raises(senders.ChannelError):
        senders.validate_config("email", {"host": "h", "from_addr": "a@b.c\nBcc: evil@x.y", "to_addrs": ["x@y.z"]})


def test_secrets_are_never_returned_by_the_api(client):
    ch = make(client, kind="webhook", config={"url": "https://example.com/hook/SECRET-TOKEN", "secret": "s3cr3t"})
    text = json.dumps(client.get("/api/notifications").json())
    assert "SECRET-TOKEN" not in text and "s3cr3t" not in text
    assert ch["config"] == {"url_host": "example.com", "has_url": True, "has_secret": True}
    mail = make(client, name="Mail", kind="email", config={
        "host": "smtp.example.com", "from_addr": "h@example.com", "to_addrs": "a@x.org; b@x.org", "password": "pw123"})
    assert "pw123" not in json.dumps(client.get("/api/notifications").json())
    assert mail["config"]["has_password"] is True and mail["config"]["to_addrs"] == ["a@x.org", "b@x.org"]


def test_updating_without_a_secret_keeps_the_old_one(client, engine):
    ch = make(client, kind="webhook", config={"url": "https://example.com/h", "secret": "keepme"})
    client.patch(f"/api/notifications/{ch['id']}", json={"config": {"url": "https://example.com/h2"}})
    with Session(engine) as s:
        row = s.get(NotificationChannelRow, ch["id"])
        assert row.config == {"url": "https://example.com/h2", "secret": "keepme"}


def test_channel_crud(client):
    ch = make(client)
    assert client.get("/api/notifications").json()["items"][0]["name"] == "Chat"
    r = client.patch(f"/api/notifications/{ch['id']}", json={"name": "  Ops   chat ", "min_severity": "critical", "enabled": False})
    assert r.json()["name"] == "Ops chat" and r.json()["min_severity"] == "critical" and r.json()["enabled"] is False
    assert client.patch("/api/notifications/999", json={}).status_code == 404
    assert client.delete(f"/api/notifications/{ch['id']}").status_code == 200
    assert client.get("/api/notifications").json()["items"] == []


# ---- delivery --------------------------------------------------------------------------------------------------
def test_each_kind_posts_the_right_shape(post):
    senders.send_http("slack", {"url": "https://s"}, "Subj", "Body", {}, post)
    senders.send_http("discord", {"url": "https://d"}, "Subj", "x" * 5000, {}, post)
    senders.send_http("webhook", {"url": "https://w"}, "Subj", "Body", {"alert": {"id": 1}}, post)
    slack, discord, hook = (c[1] for c in post.calls)
    assert slack == {"text": "*Subj*\nBody"} and len(discord["content"]) <= senders.MAX_DISCORD
    assert hook["source"] == "horizon-events" and hook["alert"] == {"id": 1}


def test_webhook_is_signed_when_a_secret_is_set(post):
    senders.send_http("webhook", {"url": "https://w", "secret": "k"}, "S", "T", {}, post)
    _, _, headers = post.calls[0]
    assert "X-Horizon-Signature" in headers
    senders.send_http("webhook", {"url": "https://w"}, "S", "T", {}, post)
    assert "X-Horizon-Signature" not in post.calls[1][2]


def test_signature_matches_the_body():
    seen = {}

    def capture(url, body, headers, timeout):
        seen.update(body=body, headers=headers)
        return 204
    senders.send_http("webhook", {"url": "https://w", "secret": "k"}, "S", "T", {}, capture)
    expected = hmac.new(b"k", seen["body"], hashlib.sha256).hexdigest()
    assert seen["headers"]["X-Horizon-Signature"] == f"sha256={expected}"


def test_a_non_2xx_answer_is_an_error():
    with pytest.raises(senders.SendError, match="500"):
        senders.send_http("slack", {"url": "https://s"}, "S", "T", {}, FakePost(status=500))


def test_email_uses_starttls_login_and_attachments():
    smtp = FakeSmtp()
    cfg = {"host": "smtp.x", "port": 587, "security": "starttls", "username": "u", "password": "p",
           "from_addr": "h@x.org", "to_addrs": ["a@x.org", "b@x.org"]}
    senders.send_email(cfg, "Sub\nject", "hello", [("r.html", b"<p>hi</p>", "text/html")], smtp)
    kinds = [e[0] for e in smtp.log]
    assert kinds == ["connect", "starttls", "login", "send"]
    msg = smtp.log[-1][1]
    assert msg["To"] == "a@x.org, b@x.org" and "\n" not in msg["Subject"]
    assert [p.get_filename() for p in msg.iter_attachments()] == ["r.html"]


def test_email_failure_becomes_a_send_error():
    cfg = {"host": "h", "port": 25, "security": "none", "username": "u", "password": "p", "from_addr": "a@b.c", "to_addrs": ["x@y.z"]}
    with pytest.raises(senders.SendError):
        senders.send_email(cfg, "S", "T", None, FakeSmtp(fail=True))


# ---- the test button and the dispatch --------------------------------------------------------------------------
def test_the_test_button_reports_success_and_failure(client, post):
    ch = make(client)
    r = client.post(f"/api/notifications/{ch['id']}/test").json()
    assert r["ok"] is True and r["channel"]["sent_count"] == 1 and len(post.calls) == 1
    post.status = 404
    r = client.post(f"/api/notifications/{ch['id']}/test").json()
    assert r["ok"] is False and "404" in r["error"] and r["channel"]["last_error"] == r["error"]


def test_new_alerts_go_to_channels_at_or_below_their_severity(client, post, monkeypatch):
    monkeypatch.setenv("HORIZON_NOTIFY_SYNC", "1")
    make(client, name="Critical only", min_severity="critical", config={"url": "https://hooks.slack.com/c"})
    make(client, name="Everything", min_severity="low", kind="discord", config={"url": "https://discord.com/api/webhooks/x"})
    make(client, name="Off", min_severity="low", enabled=False, config={"url": "https://hooks.slack.com/off"})
    data = (SAMPLES / "linux_auth.log").read_bytes()
    r = client.post("/api/imports", files={"file": ("a.log", data)}, data={"source_type": "linux_auth"}).json()
    assert r["alerts_created"] > 0
    urls = [c[0] for c in post.calls]
    assert "https://hooks.slack.com/off" not in urls
    assert urls.count("https://discord.com/api/webhooks/x") == r["alerts_created"]
    critical = [a for a in client.get("/api/alerts?severity=critical").json()["items"]]
    assert urls.count("https://hooks.slack.com/c") == len(critical)
    # importing the same file again creates no new alert, so nothing more is sent
    before = len(post.calls)
    client.post("/api/imports", files={"file": ("a.log", data)}, data={"source_type": "linux_auth"})
    assert len(post.calls) == before


def test_a_failing_channel_never_breaks_the_import(client, monkeypatch):
    monkeypatch.setenv("HORIZON_NOTIFY_SYNC", "1")
    set_service(NotificationService(post=FakePost(error="could not reach the server: down")))
    try:
        ch = make(client, min_severity="low")
        data = (SAMPLES / "linux_auth.log").read_bytes()
        r = client.post("/api/imports", files={"file": ("a.log", data)}, data={"source_type": "linux_auth"})
        assert r.status_code in (200, 201)
        row = next(i for i in client.get("/api/notifications").json()["items"] if i["id"] == ch["id"])
        assert "down" in row["last_error"] and row["sent_count"] == 0
    finally:
        set_service(NotificationService())


def test_dispatch_async_is_a_no_op_without_alerts():
    service_module.dispatch_async(None, [])  # must not even touch the engine
