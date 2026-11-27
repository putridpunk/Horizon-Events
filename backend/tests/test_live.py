import asyncio
import json
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.live.bus import LiveBus, TooManySubscribers
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


def test_a_subscriber_hears_changes_published_from_another_thread():
    async def scenario():
        bus = LiveBus()
        queue = bus.subscribe()
        threading.Thread(target=bus.publish, args=("alerts", "events", "alerts")).start()
        message = await asyncio.wait_for(queue.get(), timeout=2)
        bus.unsubscribe(queue)
        return message, bus.subscribers
    message, left = asyncio.run(scenario())
    assert message == {"changed": ["alerts", "events"]} and left == 0


def test_publishing_with_nobody_listening_or_nothing_to_say_is_harmless():
    bus = LiveBus()
    bus.publish("alerts")
    bus.publish()


def test_a_slow_subscriber_never_blocks_or_breaks_the_publisher():
    async def scenario():
        bus = LiveBus()
        queue = bus.subscribe()
        for _ in range(500):
            bus.publish("events")
        await asyncio.sleep(0.05)
        return queue.qsize()
    assert asyncio.run(scenario()) == 50  # the queue is capped; the rest are dropped


def test_there_is_a_limit_on_open_dashboards():
    async def scenario():
        bus = LiveBus(max_subscribers=2)
        bus.subscribe(), bus.subscribe()
        with pytest.raises(TooManySubscribers):
            bus.subscribe()
    asyncio.run(scenario())


def test_the_stream_endpoint_sends_a_change_event(client):
    from app.live.bus import bus
    timer = threading.Timer(0.6, bus.publish, args=("alerts",))
    timer.start()
    try:
        with client.stream("GET", "/api/stream", params={"limit": 1}) as r:
            assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
            assert r.headers["cache-control"] == "no-cache"
            body = "".join(r.iter_text())
    finally:
        timer.cancel()
    assert "retry: 3000" in body
    data = next(line[6:] for line in body.splitlines() if line.startswith("data: "))
    assert json.loads(data) == {"changed": ["alerts"]} and "event: change" in body
    assert bus.subscribers == 0  # the connection was cleaned up


def test_importing_logs_tells_the_dashboard(client, monkeypatch):
    seen = []
    monkeypatch.setattr("app.services.ingestion.bus", type("B", (), {"publish": lambda self, *a: seen.append(a)})())
    data = (SAMPLES / "linux_auth.log").read_bytes()
    client.post("/api/imports", files={"file": ("a.log", data)}, data={"source_type": "linux_auth"})
    assert seen and set(seen[0]) >= {"events", "alerts"}
    seen.clear()  # the same file again stores nothing new, so nobody is bothered
    client.post("/api/imports", files={"file": ("a.log", data)}, data={"source_type": "linux_auth"})
    assert seen == []


def test_changing_an_alert_tells_the_dashboard(client, monkeypatch):
    data = (SAMPLES / "linux_auth.log").read_bytes()
    client.post("/api/imports", files={"file": ("a.log", data)}, data={"source_type": "linux_auth"})
    alert = client.get("/api/alerts").json()["items"][0]
    seen = []
    monkeypatch.setattr("app.api.alerts.bus", type("B", (), {"publish": lambda self, *a: seen.append(a)})())
    client.patch(f"/api/alerts/{alert['id']}", json={"status": "INVESTIGATING"})
    client.patch(f"/api/alerts/{alert['id']}/triage", json={"assignee": "Ana"})
    assert [set(s) for s in seen] == [{"alerts", "incidents"}, {"alerts"}]
