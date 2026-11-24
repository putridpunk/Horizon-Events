import hashlib

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import AlertRow, EventRow
from app.database.scan_models import ScanRow
from app.scanning.defender import CLEAN, ERROR, THREAT, Finding, ScanOutcome
from app.scanning.service import ScanBusy, ScanService, record_detection, sha256_file, validate_paths


@pytest.fixture
def factory(engine):
    return lambda: Session(engine, expire_on_commit=False)


def make_files(tmp_path):
    good = tmp_path / "good.txt"
    good.write_text("fine")
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"not really malware")
    return good, bad


def fake_scanner(bad):
    def scan(path):
        if path == str(bad):
            return ScanOutcome(THREAT, [Finding("Trojan:Win32/Test", str(bad))])
        if path.endswith("broken"):
            return ScanOutcome(ERROR, message="Defender failed")
        return ScanOutcome(CLEAN)
    return scan


# ---- path validation -------------------------------------------------------------------------------------------
def test_validate_accepts_existing_absolute_paths_and_drops_duplicates(tmp_path):
    good, _ = make_files(tmp_path)
    assert validate_paths([str(good), str(tmp_path), str(good)]) == [str(good), str(tmp_path)]


@pytest.mark.parametrize("bad", [None, [], "x", [""], [" "], [5], ["relative/file.txt"], [r"\\host\share\f.exe"],
                                 ["//host/share/f.exe"], [r"\\?\C:\Windows"], ["a\x00b"]])
def test_validate_refuses_bad_input(bad):
    with pytest.raises(ValueError):
        validate_paths(bad)


def test_validate_refuses_missing_paths(tmp_path):
    with pytest.raises(ValueError, match="Not found"):
        validate_paths([str(tmp_path / "nope")])


def test_validate_limits_the_number_of_items(tmp_path):
    with pytest.raises(ValueError, match="at most"):
        validate_paths([str(tmp_path)] * 1 + [str(tmp_path / f"{i}") for i in range(60)])


def test_sha256_of_a_file_and_non_files(tmp_path):
    good, _ = make_files(tmp_path)
    assert sha256_file(str(good)) == hashlib.sha256(b"fine").hexdigest()
    assert sha256_file(str(tmp_path)) is None
    assert sha256_file(str(tmp_path / "gone")) is None
    assert sha256_file(str(good), limit=1) is None


# ---- detections become alerts ----------------------------------------------------------------------------------
def test_record_detection_creates_a_critical_alert_with_an_event(session):
    alert_id = record_detection(session, Finding("Virus:DOS/EICAR_Test_File", r"C:\t\e.txt"), "ab" * 32)
    session.commit()
    alert = session.get(AlertRow, alert_id)
    assert (alert.rule_id, alert.severity, alert.status) == ("HZ-008", "critical", "OPEN")
    assert "EICAR" in alert.description and "ab" * 32 in alert.description
    event = session.scalars(select(EventRow)).one()
    assert event.source == "file_scan" and event.extra["sha256"] == "ab" * 32 and event.severity == "critical"


def test_the_same_file_and_threat_does_not_raise_a_second_alert(session):
    finding = Finding("Trojan:Win32/Test", r"C:\t\bad.bin")
    first = record_detection(session, finding, "cd" * 32)
    second = record_detection(session, finding, "cd" * 32)
    session.commit()
    assert first == second and len(session.scalars(select(AlertRow)).all()) == 1


def test_a_different_threat_in_the_same_file_is_a_new_alert(session):
    a = record_detection(session, Finding("Trojan:A", r"C:\f"), "ef" * 32)
    b = record_detection(session, Finding("Trojan:B", r"C:\f"), "ef" * 32)
    assert a != b


# ---- the service -----------------------------------------------------------------------------------------------
def test_scan_reports_each_target_and_raises_alerts_only_for_threats(factory, tmp_path):
    good, bad = make_files(tmp_path)
    broken = tmp_path / "broken"
    broken.write_text("x")
    service = ScanService(factory, scanner=fake_scanner(bad))
    started = service.start([str(good), str(bad), str(broken)])
    assert started["status"] == "running" and started["total"] == 3
    service.wait()
    scan = service.get(started["id"])
    assert scan["status"] == "completed" and scan["done"] == 3 and scan["threats"] == 1
    by_path = {r["path"]: r for r in scan["results"]}
    assert by_path[str(good)]["status"] == "clean"
    assert by_path[str(broken)]["status"] == "error" and by_path[str(broken)]["message"] == "Defender failed"
    threat = by_path[str(bad)]["threats"][0]
    assert threat["threat"] == "Trojan:Win32/Test" and threat["sha256"] == hashlib.sha256(b"not really malware").hexdigest()
    with factory() as s:
        assert [a.rule_id for a in s.scalars(select(AlertRow))] == ["HZ-008"]


def test_an_unexpected_failure_marks_the_scan_failed(factory, tmp_path):
    good, _ = make_files(tmp_path)

    def boom(path):
        raise RuntimeError("kaput")

    service = ScanService(factory, scanner=boom)
    scan_id = service.start([str(good)])["id"]
    service.wait()
    scan = service.get(scan_id)
    assert scan["status"] == "failed" and "kaput" in scan["error"] and scan["finished_at"]


def test_only_one_scan_runs_at_a_time(factory, tmp_path):
    import threading
    good, _ = make_files(tmp_path)
    release = threading.Event()

    def slow(path):
        release.wait(5)
        return ScanOutcome(CLEAN)

    service = ScanService(factory, scanner=slow)
    service.start([str(good)])
    with pytest.raises(ScanBusy):
        service.start([str(good)])
    release.set()
    service.wait()
    service.start([str(good)])  # allowed again once the first has finished
    service.wait()


def test_a_scan_left_running_by_a_previous_session_is_closed(factory):
    with factory() as s:
        from app.domain import utcnow
        s.add(ScanRow(created_at=utcnow(), status="running", targets=["x"], results=[]))
        s.commit()
    ScanService(factory, scanner=lambda p: ScanOutcome(CLEAN))
    with factory() as s:
        row = s.scalars(select(ScanRow)).one()
        assert row.status == "failed" and "closed" in row.error


def test_recent_lists_newest_first(factory, tmp_path):
    good, _ = make_files(tmp_path)
    service = ScanService(factory, scanner=lambda p: ScanOutcome(CLEAN))
    first = service.start([str(good)])["id"]
    service.wait()
    second = service.start([str(good)])["id"]
    service.wait()
    assert [s["id"] for s in service.recent()] == [second, first]
