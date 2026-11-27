from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.alerts import triage
from app.database.connection import get_session
from app.database.notification_models import NotificationChannelRow, ReportScheduleRow
from app.domain import utcnow
from app.main import app
from app.notifications.service import NotificationService, set_service
from app.reports import scheduler
from tests.test_notifications import FakePost, FakeSmtp

SAMPLES = Path(__file__).resolve().parents[2] / "sample_logs"


@pytest.fixture
def client(engine, tmp_path):
    def override():
        with Session(engine, expire_on_commit=False) as s:
            yield s
    app.dependency_overrides[get_session] = override
    app.state.report_dir = str(tmp_path / "reports")
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def alerts(client):
    data = (SAMPLES / "linux_auth.log").read_bytes()
    client.post("/api/imports", files={"file": ("a.log", data)}, data={"source_type": "linux_auth"})
    return client.get("/api/alerts?limit=500").json()["items"]


# ---- triage ----------------------------------------------------------------------------------------------------
def test_alerts_start_unassigned_with_age_and_target_time(alerts):
    a = alerts[0]
    assert a["assignee"] is None and a["tags"] == [] and a["age_minutes"] >= 0 and a["sla_minutes"] > 0
    assert "sla_due_at" in a and isinstance(a["sla_breached"], bool)


def test_assign_and_tag_an_alert_and_record_it_in_history(client, alerts):
    aid = alerts[0]["id"]
    r = client.patch(f"/api/alerts/{aid}/triage", json={"assignee": "  Ana   Silva ", "tags": ["Phishing", "vip ", "phishing"]})
    assert r.status_code == 200
    body = r.json()
    assert body["assignee"] == "Ana Silva" and body["tags"] == ["phishing", "vip"]
    notes = [h["note"] for h in body["history"]]
    assert "Assigned to Ana Silva" in notes and "Tags: phishing, vip" in notes
    # changing only the tags leaves the owner alone, and no history line is added for an unchanged value
    r = client.patch(f"/api/alerts/{aid}/triage", json={"tags": ["vip", "phishing"]})
    assert r.json()["assignee"] == "Ana Silva" and len(r.json()["history"]) == len(body["history"]) + 1
    r = client.patch(f"/api/alerts/{aid}/triage", json={"tags": ["vip", "phishing"]})
    assert len(r.json()["history"]) == len(body["history"]) + 1


def test_unassigning_clears_the_owner(client, alerts):
    aid = alerts[0]["id"]
    client.patch(f"/api/alerts/{aid}/triage", json={"assignee": "Ana"})
    r = client.patch(f"/api/alerts/{aid}/triage", json={"assignee": None})
    assert r.json()["assignee"] is None and r.json()["history"][-1]["note"] == "Unassigned"


@pytest.mark.parametrize("body", [
    {"assignee": "x" * 101}, {"assignee": "Unassigned"}, {"tags": [f"t{i}" for i in range(11)]},
    {"tags": ["x" * 31]}, {"tags": ["<script>"]},
])
def test_bad_triage_values_are_refused(client, alerts, body):
    assert client.patch(f"/api/alerts/{alerts[0]['id']}/triage", json=body).status_code == 422


def test_triage_of_a_missing_alert_is_404(client):
    assert client.patch("/api/alerts/9999/triage", json={"assignee": "x"}).status_code == 404


def test_filter_alerts_by_owner_unassigned_and_tag(client, alerts):
    a, b = alerts[0]["id"], alerts[1]["id"]
    client.patch(f"/api/alerts/{a}/triage", json={"assignee": "Ana", "tags": ["vip"]})
    client.patch(f"/api/alerts/{b}/triage", json={"assignee": "Rui"})
    ids = lambda q: {i["id"] for i in client.get(f"/api/alerts?limit=500&{q}").json()["items"]}  # noqa: E731
    assert ids("assignee=ana") == {a} and ids("assignee=Rui") == {b} and ids("tag=VIP") == {a}
    assert ids("assignee=unassigned") == {i["id"] for i in alerts} - {a, b}
    assert client.get("/api/alerts?assignee=Ana").json()["total"] == 1
    assert client.get("/api/alerts/tags").json() == {"tags": ["vip"], "assignees": ["Ana", "Rui"]}


def test_resolved_alerts_are_never_late(client, alerts):
    a = alerts[0]
    row = triage.view(type("A", (), {"severity": "critical", "status": "OPEN", "created_at": utcnow() - timedelta(hours=2)})(), None)
    assert row["sla_breached"] is True and row["age_minutes"] >= 120
    done = triage.view(type("A", (), {"severity": "critical", "status": "RESOLVED", "created_at": utcnow() - timedelta(hours=2)})(), None)
    assert done["sla_breached"] is False
    assert a["sla_minutes"] == triage.SLA_MINUTES[a["severity"]]


# ---- scheduling ------------------------------------------------------------------------------------------------
def test_next_run_is_at_seven_utc():
    now = datetime(2026, 11, 27, 9, 30)  # a Friday
    assert scheduler.next_run_after("daily", now) == datetime(2026, 11, 28, 7, 0)
    assert scheduler.next_run_after("daily", datetime(2026, 11, 27, 6, 0)) == datetime(2026, 11, 27, 7, 0)
    assert scheduler.next_run_after("weekly", now) == datetime(2026, 11, 30, 7, 0)  # the next Monday
    assert scheduler.next_run_after("weekly", datetime(2026, 11, 30, 7, 0)) == datetime(2026, 12, 7, 7, 0)
    with pytest.raises(scheduler.ScheduleError):
        scheduler.next_run_after("hourly", now)


def test_schedule_crud_and_validation(client):
    r = client.post("/api/report-schedules", json={"name": "Weekly", "frequency": "weekly", "format": "html"})
    assert r.status_code == 201 and r.json()["next_run"] and r.json()["last_run"] is None
    sid = r.json()["id"]
    assert client.post("/api/report-schedules", json={"name": "x", "frequency": "hourly"}).status_code == 422
    assert client.post("/api/report-schedules", json={"name": "x", "format": "pdf"}).status_code == 422
    assert client.post("/api/report-schedules", json={"name": " ", "frequency": "daily"}).status_code == 422
    assert client.post("/api/report-schedules", json={"name": "x", "email_channel_id": 99}).status_code == 422
    r = client.patch(f"/api/report-schedules/{sid}", json={"frequency": "daily", "enabled": False})
    assert r.json()["frequency"] == "daily" and r.json()["enabled"] is False
    assert client.delete(f"/api/report-schedules/{sid}").status_code == 200
    assert client.delete(f"/api/report-schedules/{sid}").status_code == 404


def test_run_now_saves_a_report_and_it_can_be_downloaded(client, alerts, tmp_path):
    sid = client.post("/api/report-schedules", json={"name": "Daily", "frequency": "daily", "format": "csv"}).json()["id"]
    assert client.get(f"/api/report-schedules/{sid}/latest").status_code == 404
    r = client.post(f"/api/report-schedules/{sid}/run").json()
    assert r["last_error"] is None and r["last_file"].startswith(f"report-{sid}-") and r["last_file"].endswith(".csv")
    assert (tmp_path / "reports" / r["last_file"]).is_file()
    got = client.get(f"/api/report-schedules/{sid}/latest")
    assert got.status_code == 200 and got.headers["content-type"].startswith("text/csv")


def test_due_schedules_run_and_move_on_and_disabled_ones_do_not(engine, tmp_path):
    now = datetime(2026, 11, 27, 8, 0)
    with Session(engine, expire_on_commit=False) as s:
        s.add_all([
            ReportScheduleRow(name="due", frequency="daily", format="json", created_at=now, next_run=now - timedelta(hours=1)),
            ReportScheduleRow(name="later", frequency="daily", format="json", created_at=now, next_run=now + timedelta(hours=1)),
            ReportScheduleRow(name="off", frequency="daily", format="json", created_at=now, next_run=now - timedelta(hours=1), enabled=False)])
        s.commit()
        assert scheduler.run_due(s, tmp_path, now) == 1
        due = s.query(ReportScheduleRow).filter_by(name="due").one()
        assert due.last_run == now and due.next_run == datetime(2026, 11, 28, 7, 0) and due.last_error is None
        assert s.query(ReportScheduleRow).filter_by(name="off").one().last_run is None
        assert scheduler.run_due(s, tmp_path, now) == 0


def test_a_scheduled_report_is_emailed_with_the_file_attached(engine, tmp_path):
    smtp = FakeSmtp()
    set_service(NotificationService(post=FakePost(), smtp_factory=smtp))
    try:
        now = datetime(2026, 11, 27, 8, 0)
        with Session(engine, expire_on_commit=False) as s:
            ch = NotificationChannelRow(name="Mail", kind="email", created_at=now, min_severity="high", config={
                "host": "smtp.x", "port": 587, "security": "none", "username": "", "password": "",
                "from_addr": "h@x.org", "to_addrs": ["boss@x.org"]})
            s.add(ch)
            s.flush()
            row = ReportScheduleRow(name="Weekly", frequency="weekly", format="html", created_at=now,
                                    next_run=now, email_channel_id=ch.id)
            s.add(row)
            s.commit()
            scheduler.run_due(s, tmp_path, now)
            msg = next(e[1] for e in smtp.log if e[0] == "send")
            assert [p.get_filename() for p in msg.iter_attachments()] == [row.last_file]
            assert row.last_error is None and ch.sent_count == 1
    finally:
        set_service(NotificationService())


def test_an_email_failure_is_recorded_but_the_report_is_still_saved(engine, tmp_path):
    set_service(NotificationService(post=FakePost(), smtp_factory=FakeSmtp(fail=True)))
    try:
        now = datetime(2026, 11, 27, 8, 0)
        with Session(engine, expire_on_commit=False) as s:
            ch = NotificationChannelRow(name="Mail", kind="email", created_at=now, min_severity="high", config={
                "host": "smtp.x", "port": 25, "security": "none", "username": "u", "password": "p",
                "from_addr": "h@x.org", "to_addrs": ["boss@x.org"]})
            s.add(ch)
            s.flush()
            row = ReportScheduleRow(name="Weekly", frequency="daily", format="json", created_at=now, next_run=now,
                                    email_channel_id=ch.id)
            s.add(row)
            s.commit()
            scheduler.run_due(s, tmp_path, now)
            assert row.last_error.startswith("Saved, but the email failed") and (tmp_path / row.last_file).is_file()
    finally:
        set_service(NotificationService())


def test_old_reports_are_pruned(engine, tmp_path):
    for i in range(scheduler.KEEP_FILES + 5):
        (tmp_path / f"report-1-2026010{i % 10}-{i:04d}.json").write_text("{}")
    (tmp_path / "report-2-keep.json").write_text("{}")
    scheduler._prune(tmp_path, 1)
    assert len(list(tmp_path.glob("report-1-*"))) == scheduler.KEEP_FILES and (tmp_path / "report-2-keep.json").exists()


def test_a_channel_used_by_a_schedule_cannot_be_deleted(client):
    ch = client.post("/api/notifications", json={"name": "Mail", "kind": "email", "config": {
        "host": "smtp.x", "from_addr": "h@x.org", "to_addrs": ["b@x.org"]}}).json()
    client.post("/api/report-schedules", json={"name": "W", "email_channel_id": ch["id"]})
    assert client.delete(f"/api/notifications/{ch['id']}").status_code == 409
    webhook = client.post("/api/notifications", json={"name": "W", "kind": "webhook", "config": {"url": "https://x.org/h"}}).json()
    assert client.post("/api/report-schedules", json={"name": "bad", "email_channel_id": webhook["id"]}).status_code == 422
