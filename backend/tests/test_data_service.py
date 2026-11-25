import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.data.service import (BACKUP_SUFFIX, PENDING, DataError, DataService, apply_pending_restore, get_retention_days,
                              purge_old_events, set_retention_days)
from app.database.connection import init_db, make_engine
from app.database.models import AlertEventLink, AlertRow, EventRow
from app.domain import utcnow
from app.main import app


def add_event(session, age_days, raw):
    row = EventRow(fingerprint=raw, timestamp=utcnow() - timedelta(days=age_days), source="t", event_type="generic",
                   severity="low", message="m", raw=raw)
    session.add(row)
    session.flush()
    return row


# ---- retention -------------------------------------------------------------------------------------------------
def test_old_events_are_removed_and_recent_ones_kept(session):
    old, new = add_event(session, 100, "old"), add_event(session, 5, "new")
    assert purge_old_events(session, 30) == 1
    assert [e.raw for e in session.scalars(select(EventRow))] == ["new"]
    assert old.id != new.id


def test_events_that_back_an_alert_are_never_removed(session):
    kept = add_event(session, 400, "evidence")
    add_event(session, 400, "plain")
    alert = AlertRow(rule_id="HZ-001", rule_name="r", severity="high", status="OPEN", key="k", description="d",
                     created_at=utcnow(), last_seen=utcnow())
    session.add(alert)
    session.flush()
    session.add(AlertEventLink(alert_id=alert.id, event_id=kept.id))
    session.flush()
    assert purge_old_events(session, 30) == 1
    assert [e.raw for e in session.scalars(select(EventRow))] == ["evidence"]


def test_zero_days_keeps_everything(session):
    add_event(session, 4000, "ancient")
    assert purge_old_events(session, 0) == 0 and session.scalar(select(EventRow.id)) is not None


def test_retention_setting_roundtrip_and_validation(session):
    assert get_retention_days(session) == 0
    assert set_retention_days(session, 90) == 90 and get_retention_days(session) == 90
    for bad in (-1, 99999, "30", True, None, 1.5):
        with pytest.raises(DataError):
            set_retention_days(session, bad)


# ---- a real file database --------------------------------------------------------------------------------------
@pytest.fixture
def file_engine(tmp_path):
    engine = make_engine(f"sqlite:///{(tmp_path / 'horizon.db').as_posix()}")
    init_db(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def svc(file_engine, tmp_path):
    (tmp_path / "data").mkdir()
    return DataService(lambda: Session(file_engine, expire_on_commit=False), file_engine, tmp_path / "data")


def seed(file_engine):
    with Session(file_engine) as s:
        add_event(s, 1, "keep-me")
        s.commit()


def test_status_reports_counts_and_size(svc, file_engine):
    seed(file_engine)
    st = svc.status()
    assert st["events"] == 1 and st["backups_available"] is True and st["database_bytes"] > 0
    assert st["retention_days"] == 0 and st["restore_pending"] is False


def test_backup_is_a_real_copy_of_the_data(svc, file_engine, tmp_path):
    seed(file_engine)
    out = svc.backup(str(tmp_path / f"b{BACKUP_SUFFIX}"))
    assert out["bytes"] > 0
    con = sqlite3.connect(out["path"])
    assert con.execute("select raw from events").fetchall() == [("keep-me",)]
    con.close()


@pytest.mark.parametrize("name", ["b.txt", "b.db", "b"])
def test_backup_must_use_the_backup_extension(svc, tmp_path, name):
    with pytest.raises(DataError, match="must end in"):
        svc.backup(str(tmp_path / name))


def test_backup_refuses_relative_unc_missing_folders_and_foreign_files(svc, tmp_path):
    for bad in ("b.hzbackup", r"\\host\share\b.hzbackup", str(tmp_path / "nope" / "b.hzbackup"), ""):
        with pytest.raises(DataError):
            svc.backup(bad)
    foreign = tmp_path / f"precious{BACKUP_SUFFIX}"
    foreign.write_text("not a database")
    with pytest.raises(DataError, match="not overwritten"):
        svc.backup(str(foreign))
    assert foreign.read_text() == "not a database"


def test_an_old_backup_file_can_be_overwritten_by_a_new_one(svc, file_engine, tmp_path):
    dest = str(tmp_path / f"b{BACKUP_SUFFIX}")
    svc.backup(dest)
    seed(file_engine)
    svc.backup(dest)
    con = sqlite3.connect(dest)
    assert con.execute("select count(*) from events").fetchone()[0] == 1
    con.close()


def test_restore_is_staged_not_applied_immediately(svc, file_engine, tmp_path):
    seed(file_engine)
    backup = svc.backup(str(tmp_path / f"b{BACKUP_SUFFIX}"))["path"]
    assert svc.stage_restore(backup) == {"restart_required": True}
    assert (svc.data_dir / PENDING).exists() and svc.status()["restore_pending"] is True
    svc.cancel_restore()
    assert not (svc.data_dir / PENDING).exists()


def test_restore_refuses_files_that_are_not_backups(svc, tmp_path):
    text = tmp_path / "x.hzbackup"
    text.write_text("hello")
    other = tmp_path / "other.hzbackup"
    con = sqlite3.connect(other)
    con.execute("create table t(a)")
    con.commit()
    con.close()
    for bad in (str(text), str(other), str(tmp_path / "missing.hzbackup"), "relative.hzbackup"):
        with pytest.raises(DataError, match="not a Horizon Events backup|Choose a file"):
            svc.stage_restore(bad)
    assert not (svc.data_dir / PENDING).exists()


def test_pending_restore_replaces_the_database_and_keeps_the_old_one(svc, file_engine, tmp_path):
    seed(file_engine)
    backup = svc.backup(str(tmp_path / f"b{BACKUP_SUFFIX}"))["path"]
    with Session(file_engine) as s:  # the data changes after the backup was taken
        add_event(s, 1, "newer")
        s.commit()
    svc.stage_restore(backup)
    file_engine.dispose()
    db = tmp_path / "horizon.db"
    assert apply_pending_restore(svc.data_dir, db) is True
    con = sqlite3.connect(db)
    assert con.execute("select raw from events").fetchall() == [("keep-me",)]
    con.close()
    before = Path(str(db) + ".before-restore")
    con = sqlite3.connect(before)
    assert con.execute("select count(*) from events").fetchone()[0] == 2
    con.close()
    assert not (svc.data_dir / PENDING).exists()


def test_a_corrupt_pending_restore_is_discarded_and_the_database_untouched(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    db = tmp_path / "horizon.db"
    db.write_text("current")
    (data / PENDING).write_text("garbage")
    assert apply_pending_restore(data, db) is False
    assert db.read_text() == "current" and not (data / PENDING).exists()


def test_nothing_pending_means_nothing_happens(tmp_path):
    assert apply_pending_restore(tmp_path, tmp_path / "horizon.db") is False


def test_backups_are_unavailable_without_a_data_folder_or_on_other_databases(engine):
    svc = DataService(lambda: Session(engine, expire_on_commit=False), engine, None)
    assert svc.status()["backups_available"] is False
    with pytest.raises(DataError, match="only available"):
        svc.backup("C:/x/b.hzbackup")
    with pytest.raises(DataError, match="only available"):
        svc.stage_restore("C:/x/b.hzbackup")


# ---- API -------------------------------------------------------------------------------------------------------
@pytest.fixture
def client(svc):
    app.state.data = svc
    yield TestClient(app)
    app.state.data = None


def test_api_status_retention_and_purge(client, file_engine):
    with Session(file_engine) as s:
        add_event(s, 200, "old")
        add_event(s, 1, "new")
        s.commit()
    assert client.get("/api/data/status").json()["events"] == 2
    assert client.put("/api/data/retention", json={"days": 30}).json()["retention_days"] == 30
    res = client.post("/api/data/purge").json()
    assert res["removed"] == 1 and res["events"] == 1


def test_api_rejects_bad_retention_and_paths(client):
    for body in ({"days": -5}, {"days": 100000}):
        res = client.put("/api/data/retention", json=body)
        assert res.status_code == 422 and isinstance(res.json()["detail"], str)
    assert client.post("/api/data/backup", json={"path": "relative.hzbackup"}).status_code == 422
    assert client.post("/api/data/restore", json={"path": "C:/nope/x.hzbackup"}).status_code == 422


def test_api_backup_then_restore_staging(client, tmp_path):
    dest = str(tmp_path / f"api{BACKUP_SUFFIX}")
    assert client.post("/api/data/backup", json={"path": dest}).json()["bytes"] > 0
    assert client.post("/api/data/restore", json={"path": dest}).json() == {"restart_required": True}
    assert client.get("/api/data/status").json()["restore_pending"] is True
    assert client.delete("/api/data/restore").json() == {"restore_pending": False}
