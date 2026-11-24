import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.database.models import AlertRow
from app.domain import utcnow
from app.main import app
from app.mitigation.service import MitigationService


class FakeFirewall:
    def __init__(self):
        self.rules = set()

    def elevator(self, exe, args):
        name = next(a for a in args if a.startswith("name="))[5:]
        (self.rules.add if args[2] == "add" else self.rules.discard)(name)
        return 0, ""

    def runner(self, args, timeout):
        name = next(a for a in args if a.startswith("name="))[5:]
        return (0, f"Rule Name: {name}\n") if name in self.rules else (1, "No rules match\n")


@pytest.fixture
def parts(engine, tmp_path):
    factory = lambda: Session(engine, expire_on_commit=False)  # noqa: E731

    def override():
        with factory() as s:
            yield s

    app.dependency_overrides[get_session] = override
    fw = FakeFirewall()
    app.state.mitigation = MitigationService(factory, tmp_path / "q", elevator=fw.elevator, runner=fw.runner, own_ips=set)
    yield TestClient(app), factory, fw
    app.dependency_overrides.clear()
    app.state.mitigation = None


@pytest.fixture
def client(parts):
    return parts[0]


@pytest.fixture
def disabled(engine):
    factory = lambda: Session(engine, expire_on_commit=False)  # noqa: E731

    def override():
        with factory() as s:
            yield s

    app.dependency_overrides[get_session] = override
    app.state.mitigation = None
    yield TestClient(app), factory
    app.dependency_overrides.clear()


def add_alert(factory, rule="HZ-001", ip="8.8.4.4"):
    with factory() as s:
        alert = AlertRow(rule_id=rule, rule_name="r", severity="high", status="OPEN", key=f"{rule}|{ip}", description="d",
                         source_ip=ip, created_at=utcnow(), last_seen=utcnow())
        s.add(alert)
        s.commit()
        return alert.id


def test_settings_default_and_update(client):
    d = client.get("/api/mitigation/settings").json()
    assert d["enabled"] is True and d["block_ip"] == "ask" and d["quarantine_file"] == "ask"
    d = client.put("/api/mitigation/settings", json={"quarantine_file": "auto", "allowlist": ["8.8.4.0/24"]}).json()
    assert d["quarantine_file"] == "auto" and d["allowlist"] == ["8.8.4.0/24"]
    assert client.get("/api/mitigation/settings").json()["quarantine_file"] == "auto"


@pytest.mark.parametrize("body", [{"block_ip": "auto"}, {"block_ip": "x"}, {"block_days": 0}, {"allowlist": ["bad"]}])
def test_bad_settings_are_rejected_with_a_message(client, body):
    res = client.put("/api/mitigation/settings", json=body)
    assert res.status_code == 422 and isinstance(res.json()["detail"], str)


def test_advice_is_shown_for_every_alert_even_when_actions_are_disabled(disabled):
    client, factory = disabled
    alert_id = add_alert(factory)
    d = client.get(f"/api/mitigation/alerts/{alert_id}").json()
    assert d["enabled"] is False and d["actions"] == [] and any("block the source IP" in a for a in d["advice"])
    assert client.get("/api/mitigation/settings").json()["enabled"] is False


@pytest.mark.parametrize("call", [lambda c: c.get("/api/mitigation/history"), lambda c: c.post("/api/mitigation/1/approve"),
                                  lambda c: c.post("/api/mitigation/1/dismiss"), lambda c: c.post("/api/mitigation/1/undo")])
def test_acting_is_refused_when_disabled(disabled, call):
    assert call(disabled[0]).status_code == 409


def test_unknown_alert_is_404(client):
    assert client.get("/api/mitigation/alerts/999").status_code == 404


def test_full_block_flow_through_the_api(parts):
    client, factory, fw = parts
    alert_id = add_alert(factory)
    d = client.get(f"/api/mitigation/alerts/{alert_id}").json()
    action = d["actions"][0]
    assert action["kind"] == "block_ip" and action["status"] == "suggested" and d["skipped"] == []

    assert client.post(f"/api/mitigation/{action['id']}/approve").json()["status"] == "running"
    app.state.mitigation.wait()
    assert client.get(f"/api/mitigation/alerts/{alert_id}").json()["actions"][0]["status"] == "done"
    assert fw.rules == {"Horizon Events block 8.8.4.4"}
    assert client.get("/api/mitigation/history").json()["items"][0]["target"] == "8.8.4.4"

    assert client.post(f"/api/mitigation/{action['id']}/undo").status_code == 200
    app.state.mitigation.wait()
    assert fw.rules == set()
    assert client.get("/api/mitigation/history").json()["items"][0]["status"] == "undone"


def test_dismiss_and_conflicts(parts):
    client, factory, _ = parts
    alert_id = add_alert(factory)
    action = client.get(f"/api/mitigation/alerts/{alert_id}").json()["actions"][0]
    assert client.post(f"/api/mitigation/{action['id']}/dismiss").json()["status"] == "dismissed"
    assert client.post(f"/api/mitigation/{action['id']}/approve").status_code == 409
    assert client.post(f"/api/mitigation/{action['id']}/undo").status_code == 409
    assert client.post("/api/mitigation/9999/approve").status_code == 404


def test_private_addresses_are_explained_not_proposed(parts):
    client, factory, _ = parts
    alert_id = add_alert(factory, ip="192.168.1.50")
    d = client.get(f"/api/mitigation/alerts/{alert_id}").json()
    assert d["actions"] == [] and "private-network" in d["skipped"][0]["reason"]
    client.put("/api/mitigation/settings", json={"block_private": True})
    assert len(client.get(f"/api/mitigation/alerts/{alert_id}").json()["actions"]) == 1
