import time

import pytest
from sqlalchemy.orm import Session

from app.database.connection import init_db, make_engine
from app.database.repositories import AlertRepository, EventRepository
from app.watcher import service as watcher_module
from app.watcher.service import WatchService

LINE = "Nov 23 14:20:{s:02d} web01 sshd[1]: Failed password for admin from 192.168.1.15 port {s} ssh2\n"


def fails(start, n):
    return "".join(LINE.format(s=s) for s in range(start, start + n))


@pytest.fixture
def make_service(engine, tmp_path):
    def _make(**kw):
        return WatchService(tmp_path / "watch", lambda: Session(engine, expire_on_commit=False), **kw)
    return _make


def events(engine):
    with Session(engine) as s:
        return EventRepository(s).search()[1]


def alerts(engine, rule="HZ-001"):
    with Session(engine) as s:
        return AlertRepository(s).list(rule_id=rule)[1]


def append(tmp_path, source, name, text):
    folder = tmp_path / "watch" / source
    folder.mkdir(parents=True, exist_ok=True)
    with open(folder / name, "ab") as f:
        f.write(text.encode())


def test_ingests_appended_lines_and_raises_alert(make_service, engine, tmp_path):
    svc = make_service()
    append(tmp_path, "linux_auth", "auth.log", fails(0, 3))
    assert svc.scan_once() == 3 and alerts(engine) == 0
    append(tmp_path, "linux_auth", "auth.log", fails(3, 9))
    assert svc.scan_once() == 9 and alerts(engine) == 1
    status = svc.status()
    assert status["total_imported"] == 12 and status["files"][0]["path"] == "linux_auth/auth.log"


def test_unknown_subfolder_and_nested_ignored(make_service, engine, tmp_path):
    svc = make_service()
    append(tmp_path, "other", "x.log", fails(0, 6))
    append(tmp_path, "linux_auth/nested", "y.log", fails(0, 6))
    assert svc.scan_once() == 0 and events(engine) == 0


def test_symlink_ignored(make_service, engine, tmp_path):
    svc = make_service()
    real = tmp_path / "real.log"
    real.write_text(fails(0, 6))
    folder = tmp_path / "watch" / "linux_auth"
    folder.mkdir(parents=True)
    try:
        (folder / "link.log").symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available")
    assert svc.scan_once() == 0


def test_pause_stops_and_resume_continues(make_service, engine, tmp_path):
    svc = make_service()
    append(tmp_path, "linux_auth", "auth.log", fails(0, 2))
    svc.pause()
    assert svc.scan_once() == 0 and events(engine) == 0 and svc.status()["paused"] is True
    svc.resume()
    assert svc.scan_once() == 2


def test_failing_file_does_not_stop_others_and_is_retried(make_service, engine, tmp_path, monkeypatch):
    real = watcher_module.import_logs
    broken = {"on": True}

    def flaky(session, stype, name, data, *a, **k):
        if name == "bad.log" and broken["on"]:
            raise RuntimeError("boom")
        return real(session, stype, name, data, *a, **k)

    monkeypatch.setattr(watcher_module, "import_logs", flaky)
    svc = make_service()
    append(tmp_path, "linux_auth", "bad.log", fails(0, 2))
    append(tmp_path, "linux_auth", "good.log", fails(10, 2))
    assert svc.scan_once() == 2
    files = {f["path"]: f for f in svc.status()["files"]}
    assert "boom" in files["linux_auth/bad.log"]["last_error"] and files["linux_auth/good.log"]["last_error"] is None
    broken["on"] = False
    assert svc.scan_once() == 2  # the failed lines are retried, not lost


def test_restart_does_not_duplicate(make_service, engine, tmp_path):
    append(tmp_path, "linux_auth", "auth.log", fails(0, 12))
    make_service().scan_once()
    before = (events(engine), alerts(engine))
    assert make_service().scan_once() == 0
    assert (events(engine), alerts(engine)) == before == (12, 1)


def test_deleted_file_does_not_crash(make_service, tmp_path):
    svc = make_service()
    append(tmp_path, "linux_auth", "auth.log", fails(0, 2))
    svc.scan_once()
    (tmp_path / "watch" / "linux_auth" / "auth.log").unlink()
    assert svc.scan_once() == 0


def test_garbage_file_counted_as_skipped(make_service, engine, tmp_path):
    svc = make_service()
    folder = tmp_path / "watch" / "linux_auth"
    folder.mkdir(parents=True)
    (folder / "junk.log").write_bytes(b"\xff\xfe junk\nmore junk\n")
    assert svc.scan_once() == 0
    f = svc.status()["files"][0]
    assert f["skipped"] == 2 and f["last_error"] is None and events(engine) == 0


def test_thread_smoke(tmp_path):
    engine = make_engine(f"sqlite:///{(tmp_path / 't.db').as_posix()}")
    init_db(engine)
    svc = WatchService(tmp_path / "watch", lambda: Session(engine, expire_on_commit=False), interval=0.1)
    svc.start()
    try:
        assert svc.status()["running"] is True
        append(tmp_path, "linux_auth", "auth.log", fails(0, 6))
        deadline = time.time() + 5
        while time.time() < deadline and events(engine) < 6:
            time.sleep(0.1)
        assert events(engine) == 6 and alerts(engine) == 1
    finally:
        svc.stop()
    assert svc.status()["running"] is False
