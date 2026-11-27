from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.database.repositories import EventRepository
from app.domain import EventType, Severity
from app.main import app
from app.search.query import SearchError, compile_query
from tests.conftest import make_event


@pytest.fixture
def repo(session):
    evs = [
        make_event(EventType.authentication_failure, "2026-11-20T10:00:00", "203.0.113.7", "admin", raw="a1 Failed password for admin"),
        make_event(EventType.authentication_failure, "2026-11-21T10:00:00", "203.0.113.8", "root", raw="a2 Failed password for root"),
        make_event(EventType.authentication_success, "2026-11-21T23:40:00", "10.1.2.3", "alice", raw="a3 Accepted password for alice", severity=Severity.low),
        make_event(EventType.privilege_escalation, "2026-11-22T09:00:00", None, "bob", raw="a4 sudo bob", severity=Severity.high),
        make_event(EventType.service_failure, "2026-11-22T11:00:00", None, None, service="nginx", raw="a5 nginx failed", severity=Severity.critical),
        make_event(EventType.generic, "2026-11-23T08:00:00", "192.168.1.5", "50%_off", raw="a6 odd name", severity=Severity.low),
    ]
    r = EventRepository(session)
    r.add_many(evs)
    session.commit()
    return r


def found(repo, text):
    rows, total = repo.search(query=text, limit=100)
    assert total == len(rows)
    return sorted(r.raw.split()[0] for r in rows)


def test_an_empty_search_matches_everything(repo):
    assert len(found(repo, "")) == 6 and len(found(repo, "   ")) == 6 and len(found(repo, None)) == 6


def test_plain_words_must_all_appear(repo):
    assert found(repo, "failed password") == ["a1", "a2"]
    assert found(repo, "FAILED") == ["a1", "a2", "a5"]
    assert found(repo, '"failed password for root"') == ["a2"]


def test_fields(repo):
    assert found(repo, "user:admin") == ["a1"] and found(repo, "user:ADMIN") == ["a1"]
    assert found(repo, "ip:203.0.113.8") == ["a2"]
    assert found(repo, "service:nginx") == ["a5"]
    assert found(repo, "type:authentication_failure") == ["a1", "a2"]
    assert found(repo, "message:m") != []  # the test events all carry the message "m"
    assert found(repo, "user:admin ip:203.0.113.8") == []


def test_exact_field_values_are_not_substrings(repo):
    assert found(repo, "user:adm") == [] and found(repo, "user:adm*") == ["a1"]


def test_address_blocks_and_wildcards(repo):
    assert found(repo, "ip:203.0.113.0/24") == ["a1", "a2"]
    assert found(repo, "ip:10.0.0.0/8") == ["a3"] and found(repo, "ip:192.168.0.0/16") == ["a6"]
    assert found(repo, "ip:203.0.113.7/32") == ["a1"]
    assert found(repo, "ip:203.*") == ["a1", "a2"]
    with pytest.raises(SearchError, match="/8, /16, /24"):
        compile_query("ip:10.0.0.0/12")
    with pytest.raises(SearchError, match="not a valid"):
        compile_query("ip:10.0.0.0/99")


def test_severity_comparisons(repo):
    assert found(repo, "severity:critical") == ["a5"]
    assert found(repo, "severity:>=high") == ["a4", "a5"]
    assert found(repo, "severity:<medium") == ["a3", "a6"]
    assert found(repo, "severity:>critical") == []
    with pytest.raises(SearchError, match="Severity must be"):
        compile_query("severity:urgent")


def test_dates_cover_whole_days(repo):
    assert found(repo, "since:2026-11-22") == ["a4", "a5", "a6"]
    assert found(repo, "until:2026-11-21") == ["a1", "a2", "a3"]
    assert found(repo, "since:2026-11-21 until:2026-11-21") == ["a2", "a3"]
    assert found(repo, "since:2026-11-21T23:00") == ["a3", "a4", "a5", "a6"]
    with pytest.raises(SearchError, match="not a date"):
        compile_query("since:yesterday")


def test_negation_with_minus_and_not(repo):
    assert found(repo, "type:authentication_failure -user:root") == ["a1"]
    assert found(repo, "type:authentication_failure NOT user:root") == ["a1"]
    assert found(repo, '-"failed password"') == ["a3", "a4", "a5", "a6"]


def test_or_binds_looser_than_and(repo):
    assert found(repo, "user:alice OR user:bob") == ["a3", "a4"]
    assert found(repo, "user:admin type:authentication_failure OR service:nginx") == ["a1", "a5"]
    assert found(repo, "user:admin AND type:authentication_failure") == ["a1"]


def test_percent_and_underscore_are_literal(repo):
    assert found(repo, "user:50%_off") == ["a6"]
    assert found(repo, "50%") == ["a6"] and found(repo, "user:5_%") == []
    assert found(repo, "user:%") == []


def test_sql_in_the_search_is_just_text(repo):
    found(repo, "user:admin' OR '1'='1")  # text, not SQL: it must not raise
    assert found(repo, "'; DROP TABLE events; --") == []
    assert len(found(repo, "")) == 6


@pytest.mark.parametrize("text,message", [
    ('"unclosed', "not closed"), ("user:", "needs a value"), ("colour:red", "Unknown field"),
    ("type:nonsense", "not an event type"), ("OR user:a", "both sides"), ("user:a OR", "ends in OR"),
    ("user:a NOT", "ends in OR or NOT"), ("x" * 501, "at most 500"), (" ".join(["a"] * 21), "at most 20 terms"),
    ('""', "Empty quotation"),
])
def test_unusable_searches_say_why(text, message):
    with pytest.raises(SearchError, match=message):
        compile_query(text)


def test_a_time_of_day_is_not_mistaken_for_a_field(repo):
    assert compile_query("10:30") is not None


# ---- API -------------------------------------------------------------------------------------------------------
@pytest.fixture
def client(engine, repo):
    def override():
        with Session(engine, expire_on_commit=False) as s:
            yield s
    app.dependency_overrides[get_session] = override
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_the_events_api_takes_a_query_and_explains_a_bad_one(client):
    r = client.get("/api/events", params={"query": "user:admin OR user:bob"})
    assert r.status_code == 200 and r.json()["total"] == 2
    bad = client.get("/api/events", params={"query": "colour:red"})
    assert bad.status_code == 422 and "Unknown field" in bad.json()["detail"]
    both = client.get("/api/events", params={"query": "severity:>=high", "event_type": "service_failure"})
    assert both.json()["total"] == 1


def test_export_csv_and_json(client):
    r = client.get("/api/events/export", params={"query": "type:authentication_failure"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    lines = r.text.strip().splitlines()
    assert lines[0].startswith("id,timestamp,source,event_type,severity") and len(lines) == 3
    assert r.headers["X-Total-Matches"] == "2" and "horizon-events.csv" in r.headers["content-disposition"]
    j = client.get("/api/events/export", params={"format": "json", "limit": 1}).json()
    assert j["total"] == 6 and j["exported"] == 1
    assert client.get("/api/events/export", params={"format": "xml"}).status_code == 422
    assert client.get("/api/events/export", params={"query": "bad:x"}).status_code == 422


def test_csv_export_defuses_spreadsheet_formulas(client, session):
    EventRepository(session).add_many([make_event(ts="2026-11-24T10:00:00", user="=HYPERLINK(\"http://evil\")", raw="f1")])
    session.commit()
    text = client.get("/api/events/export", params={"query": "since:2026-11-24"}).text
    assert "'=HYPERLINK" in text and ",=HYPERLINK" not in text


def test_saved_searches(client):
    assert client.get("/api/searches").json()["items"] == []
    r = client.post("/api/searches", json={"name": "  Root   failures ", "query": "user:root type:authentication_failure"})
    assert r.status_code == 201 and r.json()["name"] == "Root failures"
    assert client.post("/api/searches", json={"name": "root failures", "query": "user:x"}).status_code == 422  # same name
    assert client.post("/api/searches", json={"name": "Bad", "query": "colour:red"}).status_code == 422
    assert client.post("/api/searches", json={"name": "Empty", "query": " "}).status_code == 422
    assert client.post("/api/searches", json={"name": " ", "query": "user:x"}).status_code == 422
    listed = client.get("/api/searches").json()
    assert [i["name"] for i in listed["items"]] == ["Root failures"] and "user" in listed["fields"]
    assert client.delete(f"/api/searches/{r.json()['id']}").status_code == 200
    assert client.delete(f"/api/searches/{r.json()['id']}").status_code == 404
