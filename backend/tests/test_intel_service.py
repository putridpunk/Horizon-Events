from datetime import datetime, timedelta

import pytest

from app.intel import service as intel

FEODO_TEXT = "# Feodo\n203.0.113.50\n198.51.100.9\n"
T0 = datetime(2026, 11, 23, 12, 0, 0)


class Fetcher:
    def __init__(self, text=FEODO_TEXT, fail=False):
        self.text, self.fail, self.calls = text, fail, 0

    def __call__(self, url):
        self.calls += 1
        if self.fail:
            raise OSError("network down")
        return self.text


def test_refresh_updates_feed_and_replaces_entries(session):
    f = Fetcher()
    [r] = intel.refresh_feeds(session, ["feodo"], fetch=f, now=lambda: T0)
    assert r == {"feed": "feodo", "status": "updated", "entries": 2, "message": "Updated."}
    f.text = "203.0.113.51\n"
    intel.refresh_feeds(session, ["feodo"], fetch=f, now=lambda: T0 + timedelta(hours=2))
    assert intel.feed_status(session)[0]["entries"] == 1
    assert intel.enrich(session, "203.0.113.51")["listed"] and not intel.enrich(session, "203.0.113.50")["listed"]


def test_second_refresh_within_hour_is_too_soon(session):
    f = Fetcher()
    intel.refresh_feeds(session, ["feodo"], fetch=f, now=lambda: T0)
    [r] = intel.refresh_feeds(session, ["feodo"], fetch=f, now=lambda: T0 + timedelta(minutes=30))
    assert r["status"] == "too_soon" and f.calls == 1


def test_refresh_after_an_hour_allowed(session):
    f = Fetcher()
    intel.refresh_feeds(session, ["feodo"], fetch=f, now=lambda: T0)
    [r] = intel.refresh_feeds(session, ["feodo"], fetch=f, now=lambda: T0 + timedelta(minutes=61))
    assert r["status"] == "updated" and f.calls == 2


def test_failed_refresh_keeps_old_entries(session):
    intel.refresh_feeds(session, ["feodo"], fetch=Fetcher(), now=lambda: T0)
    [r] = intel.refresh_feeds(session, ["feodo"], fetch=Fetcher(fail=True), now=lambda: T0 + timedelta(hours=3))
    assert r["status"] == "error" and "network down" in r["message"] and r["entries"] == 2
    assert intel.enrich(session, "203.0.113.50")["listed"]


def test_oversize_response_rejected(monkeypatch):
    class Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n): return b"x" * n

    monkeypatch.setattr(intel.urllib.request, "urlopen", lambda *a, **k: Resp())
    with pytest.raises(ValueError, match="size limit"):
        intel.http_fetch("https://example.test/feed", max_bytes=100)


def test_http_fetch_rejects_non_https():
    with pytest.raises(ValueError):
        intel.http_fetch("http://example.test/feed")
    with pytest.raises(ValueError):
        intel.http_fetch("file:///etc/passwd")


def test_demo_feed_loaded_once(session):
    assert intel.ensure_demo_feed(session) is True
    assert intel.ensure_demo_feed(session) is False
    [feed] = intel.feed_status(session)
    assert feed["source"] == "demo" and "Synthetic" in feed["name"] and feed["entries"] == 3


def test_enrich_demo_ip_listed_and_private_not(session):
    intel.ensure_demo_feed(session)
    hit = intel.enrich(session, "198.51.100.77")
    assert hit["listed"] and hit["feeds"][0]["id"] == "demo" and "Synthetic" in hit["feeds"][0]["name"]
    assert intel.enrich(session, "192.168.1.15") == {"listed": False, "feeds": []}


def test_enrich_none_ip(session):
    intel.ensure_demo_feed(session)
    assert intel.enrich(session, None) == {"listed": False, "feeds": []}


def test_unknown_feed_id_raises_valueerror(session):
    with pytest.raises(ValueError, match="Unknown feed"):
        intel.refresh_feeds(session, ["nope"], fetch=Fetcher())
