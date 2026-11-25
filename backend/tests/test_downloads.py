import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.main import app
from app.scanning.downloads import MAX_BATCH, DownloadsError, DownloadsWatcher, load_config, save_config
from app.scanning.service import ScanBusy


class FakeScans:
    def __init__(self):
        self.started, self.busy = [], False

    def start(self, paths):
        if self.busy:
            raise ScanBusy("busy")
        for p in paths:
            if not os.path.exists(p):
                raise ValueError(f"Not found: {p}")
        self.started.append(list(paths))
        return {"id": len(self.started)}


@pytest.fixture
def factory(engine):
    return lambda: Session(engine, expire_on_commit=False)


def watcher(factory, folder, enabled=True, scans=None):
    with factory() as s:
        save_config(s, enabled=enabled, folder=str(folder))
        s.commit()
    return DownloadsWatcher(factory, scans if scans is not None else FakeScans())


def put(folder, name, text="x"):
    path = folder / name
    path.write_text(text)
    return str(path)


def test_files_that_were_already_there_are_never_scanned(factory, tmp_path):
    put(tmp_path, "old.exe")
    w = watcher(factory, tmp_path)
    for _ in range(4):
        w.tick()
    assert w.scans.started == []


def test_a_new_file_is_scanned_once_it_has_stopped_changing(factory, tmp_path):
    w = watcher(factory, tmp_path)
    w.tick()  # baseline
    new = put(tmp_path, "setup.exe")
    w.tick()  # first sighting: it might still be downloading
    assert w.scans.started == []
    w.tick()  # unchanged since the last check
    assert w.scans.started == [[new]]
    w.tick()
    w.tick()
    assert w.scans.started == [[new]]  # not scanned again


def test_a_file_that_keeps_growing_is_left_alone(factory, tmp_path):
    w = watcher(factory, tmp_path)
    w.tick()
    path = tmp_path / "big.iso"
    for i in range(1, 5):
        path.write_text("x" * i)
        w.tick()
    assert w.scans.started == []
    w.tick()
    w.tick()
    assert w.scans.started == [[str(path)]]


def test_a_changed_file_is_scanned_again(factory, tmp_path):
    w = watcher(factory, tmp_path)
    w.tick()
    path = put(tmp_path, "a.exe", "one")
    w.tick(), w.tick()
    put(tmp_path, "a.exe", "two two")
    w.tick(), w.tick()
    assert w.scans.started == [[path], [path]]


@pytest.mark.parametrize("name", ["movie.mkv.crdownload", "x.part", "y.tmp", "z.download", "w.partial", "v.opdownload"])
def test_unfinished_downloads_are_ignored(factory, tmp_path, name):
    w = watcher(factory, tmp_path)
    w.tick()
    put(tmp_path, name)
    for _ in range(4):
        w.tick()
    assert w.scans.started == []


def test_subfolders_are_not_scanned(factory, tmp_path):
    w = watcher(factory, tmp_path)
    w.tick()
    (tmp_path / "sub").mkdir()
    put(tmp_path / "sub", "inner.exe")
    for _ in range(4):
        w.tick()
    assert w.scans.started == []


def test_when_a_scan_is_running_the_file_waits_its_turn(factory, tmp_path):
    scans = FakeScans()
    w = watcher(factory, tmp_path, scans=scans)
    w.tick()
    new = put(tmp_path, "a.exe")
    scans.busy = True
    for _ in range(4):
        w.tick()
    assert scans.started == [] and w.status()["queued"] == 1
    scans.busy = False
    w.tick()
    assert scans.started == [[new]] and w.status()["queued"] == 0


def test_a_file_deleted_before_its_turn_is_dropped(factory, tmp_path):
    w = watcher(factory, tmp_path)
    w.tick()
    new = put(tmp_path, "a.exe")
    w.tick(), w.tick()
    assert w.scans.started == [[new]]
    gone = put(tmp_path, "b.exe")
    w.tick()
    os.remove(gone)
    w.tick(), w.tick()
    assert w.scans.started == [[new]]


def test_many_files_are_scanned_in_batches(factory, tmp_path):
    w = watcher(factory, tmp_path)
    w.tick()
    for i in range(MAX_BATCH + 5):
        put(tmp_path, f"f{i}.bin")
    w.tick(), w.tick()
    assert [len(b) for b in w.scans.started] == [MAX_BATCH]
    w.tick()
    assert [len(b) for b in w.scans.started] == [MAX_BATCH, 5]
    assert w.status()["scanned"] == MAX_BATCH + 5


def test_nothing_happens_while_it_is_switched_off_and_turning_it_on_baselines_again(factory, tmp_path):
    w = watcher(factory, tmp_path, enabled=False)
    put(tmp_path, "a.exe")
    for _ in range(3):
        w.tick()
    assert w.scans.started == [] and w.status()["watching"] is False
    with factory() as s:
        save_config(s, enabled=True)
        s.commit()
    for _ in range(3):
        w.tick()
    assert w.scans.started == []  # a.exe was already there when watching began
    new = put(tmp_path, "b.exe")
    w.tick(), w.tick()
    assert w.scans.started == [[new]]


def test_a_missing_folder_is_survived(factory, tmp_path):
    w = watcher(factory, tmp_path)
    with factory() as s:
        cfg = load_config(s)
    assert cfg["enabled"] is True
    tmp = tmp_path / "gone"
    tmp.mkdir()
    w2 = watcher(factory, tmp)
    tmp.rmdir()
    w2.tick(), w2.tick()
    assert w2.scans.started == []


def test_a_new_folder_is_baselined_not_scanned(factory, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    put(other, "preexisting.exe")
    w = watcher(factory, tmp_path)
    w.tick()
    with factory() as s:
        save_config(s, folder=str(other))
        s.commit()
    for _ in range(3):
        w.tick()
    assert w.scans.started == []


def test_without_a_scan_service_nothing_is_watched(factory, tmp_path):
    w = DownloadsWatcher(factory, None)
    with factory() as s:
        save_config(s, enabled=True, folder=str(tmp_path))
        s.commit()
    w.tick()
    assert w.status()["watching"] is False


# ---- config ----------------------------------------------------------------------------------------------------
def test_defaults_are_off_with_the_downloads_folder(session):
    cfg = load_config(session)
    assert cfg["enabled"] is False and cfg["folder"] == "" and cfg["effective_folder"].endswith("Downloads")


def test_folder_validation(session, tmp_path):
    for bad in ("relative", r"\\host\share", str(tmp_path / "missing"), "a\x00b"):
        with pytest.raises(DownloadsError):
            save_config(session, folder=bad)
    assert save_config(session, enabled=True, folder=str(tmp_path))["effective_folder"] == str(tmp_path)
    assert save_config(session, folder="")["effective_folder"].endswith("Downloads")  # back to the default


# ---- API -------------------------------------------------------------------------------------------------------
@pytest.fixture
def client(factory, tmp_path):
    def override():
        with factory() as s:
            yield s
    app.dependency_overrides[get_session] = override
    app.state.downloads = DownloadsWatcher(factory, FakeScans())
    yield TestClient(app)
    app.dependency_overrides.clear()
    app.state.downloads = None


def test_api_get_and_update(client, tmp_path):
    d = client.get("/api/scans/downloads").json()
    assert d["available"] is True and d["enabled"] is False and d["watching"] is False
    d = client.put("/api/scans/downloads", json={"enabled": True, "folder": str(tmp_path)}).json()
    assert d["enabled"] is True and d["effective_folder"] == str(tmp_path)


def test_api_rejects_bad_folders_and_is_desktop_only(client):
    res = client.put("/api/scans/downloads", json={"folder": "relative"})
    assert res.status_code == 422 and isinstance(res.json()["detail"], str)
    app.state.downloads = None
    assert client.put("/api/scans/downloads", json={"enabled": True}).status_code == 409
    assert client.get("/api/scans/downloads").json()["available"] is False
