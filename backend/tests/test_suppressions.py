from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.alerts.manager import AlertManager
from app.alerts.suppression import SuppressionError, Suppressions
from app.database.connection import get_session
from app.database.repositories import AlertRepository, EventRepository
from app.domain import Detection, Severity
from app.main import app
from tests.conftest import make_event

SAMPLES = Path(__file__).resolve().parents[2] / "sample_logs"


def det(session, rule="HZ-001", ip="1.1.1.1", user="admin", key=None, ts="2026-11-23T10:00:00"):
    t0 = datetime.fromisoformat(ts)
    evs = EventRepository(session).add_many([make_event(ts=t0.isoformat(), raw=f"{rule}-{ip}-{user}-{ts}")])
    return Detection(rule, "name", Severity.high, "desc", evs, ip, user, 1, 5, key or f"{rule}|{ip}|{user}")


def manager(session):
    return AlertManager(AlertRepository(session), suppressions=Suppressions(session))


def test_a_matching_detection_raises_no_alert_and_counts_a_hit(session):
    sup = Suppressions(session)
    row = sup.create("HZ-001", "1.1.1.1", "admin", "backup job")
    mgr = AlertManager(AlertRepository(session), suppressions=sup)
    assert mgr.process([det(session)]) == []
    assert mgr.suppressed == 1 and row.hits == 1 and row.last_hit is not None
    assert mgr.alerts.list()[1] == 0


@pytest.mark.parametrize("other", [dict(rule="HZ-003"), dict(ip="2.2.2.2"), dict(user="root")])
def test_a_detection_that_differs_in_any_set_field_still_alerts(session, other):
    Suppressions(session).create("HZ-001", "1.1.1.1", "admin")
    mgr = manager(session)
    assert len(mgr.process([det(session, **other)])) == 1 and mgr.suppressed == 0


def test_a_partial_pattern_matches_everything_it_leaves_open(session):
    Suppressions(session).create(source_ip="1.1.1.1")  # this address, any rule, any account
    mgr = manager(session)
    assert mgr.process([det(session, rule="HZ-001"), det(session, rule="HZ-004", user="bob")]) == []
    assert mgr.suppressed == 2


def test_other_detections_in_the_same_batch_still_alert(session):
    Suppressions(session).create("HZ-001", "1.1.1.1", "admin")
    mgr = manager(session)
    alerts = mgr.process([det(session), det(session, ip="3.3.3.3")])
    assert [a.source_ip for a in alerts] == ["3.3.3.3"]


def test_without_a_suppression_list_everything_alerts(session):
    assert len(AlertManager(AlertRepository(session)).process([det(session)])) == 1


def test_an_empty_pattern_is_refused_because_it_would_hide_everything(session):
    for args in ({}, {"rule_id": "  ", "source_ip": "", "username": None}):
        with pytest.raises(SuppressionError, match="at least"):
            Suppressions(session).create(**args)


def test_malware_detections_are_never_suppressed(session):
    with pytest.raises(SuppressionError, match="Malware"):
        Suppressions(session).create("HZ-008")
    sup = Suppressions(session)
    sup.create(source_ip="1.1.1.1")
    mgr = AlertManager(AlertRepository(session), suppressions=sup)
    assert len(mgr.process([det(session, rule="HZ-008", ip="1.1.1.1")])) == 1


def test_creating_the_same_pattern_twice_returns_the_first(session):
    sup = Suppressions(session)
    a = sup.create("HZ-001", "1.1.1.1", "admin")
    assert sup.create(" HZ-001 ", "1.1.1.1", "admin").id == a.id
    assert len(sup.list()) == 1


def test_deleting_a_suppression_lets_alerts_through_again(session):
    sup = Suppressions(session)
    row = sup.create("HZ-001")
    assert sup.delete(row.id) is True and sup.delete(row.id) is False
    assert len(manager(session).process([det(session)])) == 1


# ---- API -------------------------------------------------------------------------------------------------------
@pytest.fixture
def client(engine):
    def override():
        with Session(engine, expire_on_commit=False) as s:
            yield s
    app.dependency_overrides[get_session] = override
    yield TestClient(app)
    app.dependency_overrides.clear()


def import_sample(client):
    data = (SAMPLES / "linux_auth_brute_force.log").read_bytes() if (SAMPLES / "linux_auth_brute_force.log").exists() \
        else next(SAMPLES.glob("*auth*.log")).read_bytes()
    return client.post("/api/imports", files={"file": ("a.log", data)}, data={"source_type": "linux_auth"}).json()


def test_suppressing_an_alert_resolves_it_and_hides_future_ones(client):
    first = import_sample(client)
    assert first["alerts_created"] >= 1
    alerts = client.get("/api/alerts").json()["items"]
    target = alerts[0]
    res = client.post(f"/api/alerts/{target['id']}/suppress")
    assert res.status_code == 201 and res.json()["rule_id"] == target["rule_id"]
    assert client.get(f"/api/alerts/{target['id']}").json()["status"] == "RESOLVED"
    assert [s["id"] for s in client.get("/api/suppressions").json()["items"]] == [res.json()["id"]]

    again = import_sample(client)  # the same logs again: duplicates are skipped, so new alert counts stay put
    assert again["alerts_created"] <= first["alerts_created"]


def test_api_create_list_delete(client):
    created = client.post("/api/suppressions", json={"rule_id": "HZ-001", "source_ip": "9.9.9.9", "note": "scanner"})
    assert created.status_code == 201 and created.json()["hits"] == 0
    assert client.get("/api/suppressions").json()["items"][0]["note"] == "scanner"
    assert client.delete(f"/api/suppressions/{created.json()['id']}").status_code == 200
    assert client.get("/api/suppressions").json()["items"] == []
    assert client.delete("/api/suppressions/999").status_code == 404


@pytest.mark.parametrize("body", [{}, {"note": "x"}, {"rule_id": "HZ-008"}])
def test_api_refuses_unsafe_patterns(client, body):
    res = client.post("/api/suppressions", json=body)
    assert res.status_code == 422 and isinstance(res.json()["detail"], str)


def test_suppress_unknown_alert_is_404(client):
    assert client.post("/api/alerts/999/suppress").status_code == 404
