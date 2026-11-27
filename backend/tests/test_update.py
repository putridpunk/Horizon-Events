import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.main import app
from app.update import check as updates
from app.version import __version__

NOW = datetime(2026, 11, 27, 10, 0)
PAGE = "https://github.com/putridpunk/Horizon-Events/releases/tag/v9.9.9"


def release(tag="v9.9.9", url=PAGE, body="Fixes things.\n\nAdds things."):
    return lambda _url: {"tag_name": tag, "html_url": url, "body": body, "published_at": "2026-11-26T09:00:00Z"}


@pytest.mark.parametrize("text,expected", [
    ("v1.5.0", (1, 5, 0)), ("1.5.0", (1, 5, 0)), (" v10.20.30 ", (10, 20, 30)), ("1.5.0-rc1", None), ("1.5", None),
    ("v1.5.0.1", None), ("latest", None), ("", None), (None, None), ("1.5.x", None)])
def test_only_plain_versions_are_compared(text, expected):
    assert updates.parse_version(text) == expected


def test_versions_compare_as_numbers_not_text(session):
    assert updates.parse_version("1.10.0") > updates.parse_version("1.9.9")


def test_this_version_is_a_plain_version():
    assert updates.parse_version(__version__) is not None


def test_a_newer_release_is_reported_with_its_page_and_notes(session):
    s = updates.check(session, release(), NOW)
    assert s["update_available"] is True and s["latest"] == "9.9.9" and s["current"] == __version__
    assert s["url"] == PAGE and s["notes"] == "Fixes things. Adds things." and s["error"] is None
    assert s["checked_at"] == NOW.isoformat()


def test_the_same_or_an_older_release_is_not_an_update(session):
    assert updates.check(session, release(f"v{__version__}"), NOW)["update_available"] is False
    s = updates.check(session, release("v0.0.1"), NOW)
    assert s["update_available"] is False and s["url"] is None and s["notes"] is None


def test_a_release_page_outside_the_project_is_not_trusted(session):
    s = updates.check(session, release(url="https://evil.example/download.exe"), NOW)
    assert s["url"] == "https://github.com/putridpunk/Horizon-Events/releases/latest"
    assert "evil" not in json.dumps(s)


def test_notes_are_cut_to_a_safe_length(session):
    assert len(updates.check(session, release(body="x " * 5000), NOW)["notes"]) <= updates.MAX_NOTES


def test_a_failed_check_is_explained_and_keeps_what_was_known(session):
    updates.check(session, release(), NOW)

    def down(_url):
        raise updates.UpdateError("Could not reach GitHub. Check the internet connection.")
    s = updates.check(session, down, NOW + timedelta(hours=1))
    assert s["error"] == "Could not reach GitHub. Check the internet connection." and s["update_available"] is True
    assert updates.check(session, release("nightly"), NOW)["error"].startswith("The latest release has a name")


def test_only_githubs_release_list_can_be_asked():
    with pytest.raises(updates.UpdateError, match="Only GitHub"):
        updates.http_get_json("https://evil.example/releases")
    with pytest.raises(updates.UpdateError, match="Only GitHub"):
        updates.http_get_json("http://api.github.com/x")


def test_automatic_checks_are_off_by_default_and_at_most_daily(session):
    calls = []

    def fetch(url):
        calls.append(url)
        return release()(url)
    assert updates.maybe_auto_check(session, fetch, NOW) is False and calls == []
    updates.set_auto(session, True)
    assert updates.maybe_auto_check(session, fetch, NOW) is True
    assert updates.maybe_auto_check(session, fetch, NOW + timedelta(hours=23)) is False
    assert updates.maybe_auto_check(session, fetch, NOW + timedelta(hours=25)) is True
    assert len(calls) == 2 and calls[0] == updates.RELEASE_API


@pytest.fixture
def client(engine):
    def override():
        with Session(engine, expire_on_commit=False) as s:
            yield s
    app.dependency_overrides[get_session] = override
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_the_api_checks_on_request_and_remembers_the_choice(client, monkeypatch):
    first = client.get("/api/update").json()
    assert first["current"] == __version__ and first["auto_check"] is False and first["checked_at"] is None
    monkeypatch.setattr(updates, "http_get_json", release())
    assert client.post("/api/update/check").json()["update_available"] is True
    assert client.get("/api/update").json()["latest"] == "9.9.9"
    assert client.put("/api/update/settings", json={"auto_check": True}).json()["auto_check"] is True
    assert client.get("/api/update").json()["auto_check"] is True


def test_a_failing_network_never_breaks_the_api(client, monkeypatch):
    def down(_url):
        raise updates.UpdateError("Could not reach GitHub. Check the internet connection.")
    monkeypatch.setattr(updates, "http_get_json", down)
    r = client.post("/api/update/check")
    assert r.status_code == 200 and "Could not reach" in r.json()["error"]


def test_every_release_has_hand_written_notes():
    notes = Path(__file__).resolve().parents[2] / "docs" / "release-notes" / f"v{__version__}.md"
    assert notes.is_file(), f"write docs/release-notes/v{__version__}.md by hand before releasing"
    text = notes.read_text(encoding="utf-8")
    assert len(text.strip()) >= 80 and "TODO" not in text and "{{" not in text
