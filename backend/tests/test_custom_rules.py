from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.database.repositories import EventRepository
from app.detection import sigma
from app.detection.custom import CustomRule, RuleError, matches, validate_params
from app.detection.registry import build_rule
from app.domain import Event, EventType, Severity
from app.main import app
from tests.conftest import make_event

SAMPLES = Path(__file__).resolve().parents[2] / "sample_logs"


def leaf(field, op, value=None, **extra):
    return {"field": field, "op": op, **({"value": value} if value is not None else {}), **extra}


def params(when, **over):
    return validate_params({"when": when, **over})


def rule(when, severity="high", **over):
    return CustomRule("CR-001", "Test rule", "Something happened", severity, params(when, **over))


# ---- validation ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("bad,message", [
    ({}, "needs conditions"),
    ({"when": {"all": []}}, "non-empty list"),
    ({"when": {"all": [leaf("colour", "eq", "x")]}}, "Unknown field"),
    ({"when": leaf("username", "like", "x")}, "Unknown test"),
    ({"when": leaf("username", "eq")}, "needs a value"),
    ({"when": leaf("username", "eq", "  ")}, "needs a value"),
    ({"when": leaf("event_type", "eq", "nonsense")}, "not an event type"),
    ({"when": leaf("severity", "eq", "urgent")}, "not a severity"),
    ({"when": leaf("username", "severity_gte", "high")}, "Severity tests"),
    ({"when": leaf("username", "cidr", "10.0.0.0/8")}, "cidr test works on source_ip"),
    ({"when": leaf("source_ip", "cidr", "10.0.0.0/99")}, "not an address"),
    ({"when": leaf("username", "raw_field", "x")}, "raw_field"),
    ({"when": leaf("username", "eq", "x" * 501)}, "at most 500"),
    ({"when": {"all": [leaf("username", "eq", "x")], "any": []}}, "nothing else"),
    ({"when": {"not": leaf("username", "eq", "x"), "field": "username"}}, "stand alone"),
    ({"when": leaf("username", "eq", "x"), "threshold": 0}, "between 1 and"),
    ({"when": leaf("username", "eq", "x"), "threshold": "many"}, "whole numbers"),
    ({"when": leaf("username", "eq", "x"), "window_minutes": 99999}, "one week"),
    ({"when": leaf("username", "eq", "x"), "group_by": "colour"}, "Group by"),
])
def test_bad_definitions_say_what_is_wrong(bad, message):
    with pytest.raises(RuleError, match=message):
        validate_params(bad)


def test_nesting_and_size_are_limited():
    deep = leaf("username", "eq", "x")
    for _ in range(7):
        deep = {"not": deep}
    with pytest.raises(RuleError, match="nested at most"):
        validate_params({"when": deep})
    with pytest.raises(RuleError, match="at most 30 conditions"):
        validate_params({"when": {"any": [leaf("username", "eq", str(i)) for i in range(31)]}})


def test_validation_returns_a_clean_copy_with_defaults():
    p = validate_params({"when": leaf("event_type", "in", "authentication_failure, unknown_user"), "junk": 1})
    assert p == {"when": {"field": "event_type", "op": "in", "value": ["authentication_failure", "unknown_user"]},
                 "threshold": 1, "window_minutes": 10, "group_by": "none"}


# ---- matching --------------------------------------------------------------------------------------------------
def ev(**kw):
    base = dict(timestamp=datetime(2026, 11, 23, 10, 0), source="windows", event_type=EventType.authentication_failure,
                severity=Severity.medium, message="Failed logon for Admin", raw="EventID=4625 TargetUserName=Admin LogonType=3",
                username="Admin", source_ip="203.0.113.7", host="WS1", service=None)
    return Event(**{**base, **kw})


@pytest.mark.parametrize("cond,expected", [
    (leaf("username", "eq", "admin"), True), (leaf("username", "ne", "admin"), False),
    (leaf("message", "contains", "FAILED"), True), (leaf("message", "not_contains", "failed"), False),
    (leaf("message", "startswith", "failed"), True), (leaf("message", "endswith", "admin"), True),
    (leaf("username", "in", ["root", "ADMIN"]), True), (leaf("host", "glob", "ws*"), True),
    (leaf("source_ip", "cidr", "203.0.113.0/24"), True), (leaf("source_ip", "cidr", "10.0.0.0/8"), False),
    (leaf("severity", "severity_gte", "medium"), True), (leaf("severity", "severity_gte", "high"), False),
    (leaf("severity", "severity_lte", "medium"), True), (leaf("service", "absent"), True), (leaf("service", "present"), False),
    (leaf("raw", "raw_field", "4625", name="EventID"), True), (leaf("raw", "raw_field", "4624", name="EventID"), False),
    (leaf("raw", "raw_field", "adm", name="TargetUserName", mode="startswith"), True),
    (leaf("raw", "raw_field", "3", name="LogonType", mode="eq"), True), (leaf("raw", "raw_field", "x", name="Missing"), False),
])
def test_each_test(cond, expected):
    assert matches(validate_params({"when": cond})["when"], ev()) is expected


def test_all_any_and_not_combine():
    when = validate_params({"when": {"all": [leaf("username", "eq", "admin"),
                                             {"any": [leaf("host", "eq", "nope"), leaf("host", "eq", "ws1")]},
                                             {"not": leaf("source_ip", "cidr", "10.0.0.0/8")}]}})["when"]
    assert matches(when, ev()) and not matches(when, ev(source_ip="10.1.1.1")) and not matches(when, ev(host="x"))


# ---- the rule --------------------------------------------------------------------------------------------------
def stored(session, *events):
    return EventRepository(session).add_many(list(events))


def test_a_single_match_raises_one_detection_per_group(session):
    r = rule(leaf("username", "eq", "root"), group_by="source_ip")
    new = stored(session, make_event(ip="1.1.1.1", user="root", raw="a"), make_event(ip="2.2.2.2", user="root", raw="b"),
                 make_event(ip="3.3.3.3", user="alice", raw="c"), make_event(ip="1.1.1.1", user="root", raw="d"))
    ds = r.evaluate(new, EventRepository(session))
    assert sorted((d.source_ip, d.occurrences, d.key) for d in ds) == [
        ("1.1.1.1", 2, "CR-001|source_ip:1.1.1.1|"), ("2.2.2.2", 1, "CR-001|source_ip:2.2.2.2|")]
    assert all(d.rule_id == "CR-001" and d.rule_name == "Test rule" and d.severity is Severity.high for d in ds)
    assert "2 matching events" in ds[0].description or "2 matching events" in ds[1].description


def test_events_without_the_grouping_value_are_skipped(session):
    r = rule(leaf("event_type", "eq", "authentication_failure"), group_by="source_ip")
    new = stored(session, make_event(ip=None, raw="x"))
    assert r.evaluate(new, EventRepository(session)) == []


def test_a_threshold_counts_matches_inside_the_window(session):
    r = rule(leaf("event_type", "eq", "authentication_failure"), threshold=3, window_minutes=5, group_by="source_ip")
    base = datetime(2026, 11, 23, 10, 0)
    new = stored(session, *[make_event(ts=(base + timedelta(minutes=i)).isoformat(), ip="1.1.1.1", raw=f"a{i}") for i in range(2)])
    assert r.evaluate(new, EventRepository(session)) == []
    more = stored(session, make_event(ts=(base + timedelta(minutes=3)).isoformat(), ip="1.1.1.1", raw="a3"))
    [d] = r.evaluate(more, EventRepository(session))  # history plus the new one reach 3
    assert d.occurrences == 3 and d.window_minutes == 5 and d.source_ip == "1.1.1.1"
    late = stored(session, make_event(ts=(base + timedelta(hours=2)).isoformat(), ip="1.1.1.1", raw="late"))
    assert r.evaluate(late, EventRepository(session)) == []  # too far from the others


def test_a_threshold_is_counted_per_group(session):
    r = rule(leaf("event_type", "eq", "authentication_failure"), threshold=2, window_minutes=5, group_by="username")
    new = stored(session, make_event(user="a", raw="1"), make_event(user="b", raw="2"), make_event(user="a", raw="3", ts="2026-11-23T10:01:00"))
    [d] = r.evaluate(new, EventRepository(session))
    assert d.username == "a"


def test_group_by_host_filters_history_by_host(session):
    evs = [make_event(raw=f"h{i}", ts=f"2026-11-23T10:0{i}:00") for i in range(3)]
    for e, h in zip(evs, ["A", "B", "A"]):
        e.host = h
    new = stored(session, *evs)
    [d] = rule(leaf("event_type", "eq", "authentication_failure"), threshold=2, group_by="host").evaluate(new, EventRepository(session))
    assert d.key == "CR-001|host:A|" and d.occurrences == 2


def test_building_from_a_stored_definition_and_a_damaged_one():
    good = {"id": "CR-007", "name": "N", "description": "D", "severity": "low",
            "params": {"when": leaf("username", "eq", "x"), "threshold": 1}}
    built = build_rule(good)
    assert built.id == "CR-007" and built.name == "N" and built.severity is Severity.low
    assert build_rule({**good, "params": {"when": {"all": []}}}) is None  # skipped, never breaks an import
    assert build_rule({"id": "CR-009", "params": None}) is None


# ---- Sigma -----------------------------------------------------------------------------------------------------
SIGMA = """
title: Admin logons from outside
description: Logons for admin accounts from public networks
level: high
detection:
  selection:
    EventID: 4625
    TargetUserName|contains:
      - admin
      - root
  filter:
    IpAddress|cidr: 10.0.0.0/8
  condition: selection and not filter
"""


def test_a_sigma_rule_becomes_a_custom_rule():
    out = sigma.convert(SIGMA)
    assert out["name"] == "Admin logons from outside" and out["severity"] == "high"
    when = out["params"]["when"]
    assert matches(when, ev(source_ip="203.0.113.7")) and not matches(when, ev(source_ip="10.2.3.4"))
    assert not matches(when, ev(username="alice")) and not matches(when, ev(raw="EventID=4624 TargetUserName=Admin", source_ip="203.0.113.7"))


def test_sigma_conditions_with_quantifiers_and_keywords():
    text = """
title: Keywords
detection:
  keywords:
    - mimikatz
    - sekurlsa
  sel_a:
    Computer: WS1
  sel_b:
    Computer: WS2
  condition: keywords or 1 of sel_*
"""
    when = sigma.convert(text)["params"]["when"]
    assert matches(when, ev(host="WS2", raw="x")) and matches(when, ev(host="other", raw="ran mimikatz now"))
    assert not matches(when, ev(host="other", raw="harmless"))
    all_of = sigma.convert(text.replace("keywords or 1 of sel_*", "all of them"))["params"]["when"]
    assert not matches(all_of, ev(host="WS1", raw="mimikatz"))


def test_sigma_wildcards_and_null():
    text = "title: T\ndetection:\n  s:\n    Computer: 'WS*'\n    ServiceName: null\n  condition: s\n"
    when = sigma.convert(text)["params"]["when"]
    assert matches(when, ev(host="WS9", service=None)) and not matches(when, ev(host="WS9", service="x"))


@pytest.mark.parametrize("text,message", [
    ("title: T\ndetection:\n  s:\n    A|re: x\n  condition: s", "not supported"),
    ("title: T\ndetection:\n  s:\n    A|base64: x\n  condition: s", "not supported"),
    ("title: T\ndetection:\n  s:\n    A: x\n  condition: s | count() > 5", "aggregation"),
    ("title: T\ndetection:\n  s:\n    A: x\n  condition: nope", "not defined"),
    ("title: T\ndetection:\n  s:\n    A: x\n  condition: 1 of zzz*", "matches no search"),
    ("title: T\ndetection:\n  s:\n    A: x\n  condition: (s", "not closed"),
    ("title: T\ndetection:\n  s:\n    A: x\n  condition: s and", "ends too early"),
    ("title: T\ndetection:\n  s:\n    A: x\n  condition: s s", "could not be read"),
    ("title: T\ndetection:\n  s:\n    A: x\n", "no condition"),
    ("title: T\ndetection:\n  condition: s\n", "no searches"),
    ("detection:\n  s:\n    A: x\n  condition: s\n", "no title"),
    ("just text", "does not look like"), (": : :\n\t- [", "not valid YAML"),
    ("title: T\ndetection:\n  s:\n    A|cidr: 1.2.3.4/8\n  condition: s", "cidr modifier works on address"),
    ("x: " + "y" * 200_000, "larger than 100 KB"),
])
def test_unsupported_sigma_is_refused_with_a_reason(text, message):
    with pytest.raises(sigma.SigmaError, match=message):
        sigma.convert(text)


def test_sigma_is_read_safely():
    with pytest.raises(sigma.SigmaError):  # safe_load never builds python objects
        sigma.convert("title: !!python/object/apply:os.system ['echo hi']\ndetection: {s: {A: x}, condition: s}")


# ---- API -------------------------------------------------------------------------------------------------------
@pytest.fixture
def client(engine):
    def override():
        with Session(engine, expire_on_commit=False) as s:
            yield s
    app.dependency_overrides[get_session] = override
    yield TestClient(app)
    app.dependency_overrides.clear()


BODY = {"name": "  Root   from outside ", "description": "Root logons", "severity": "high", "params": {
    "when": {"all": [leaf("username", "eq", "root"), {"not": leaf("source_ip", "cidr", "192.168.0.0/16")}]},
    "threshold": 1, "group_by": "source_ip"}}


def import_auth(client):
    data = (SAMPLES / "linux_auth.log").read_bytes()
    return client.post("/api/imports", files={"file": ("a.log", data)}, data={"source_type": "linux_auth"}).json()


def test_a_custom_rule_is_created_listed_and_used_on_the_next_import(client):
    r = client.post("/api/rules/custom", json={**BODY, "params": {"when": leaf("event_type", "eq", "authentication_failure"), "group_by": "source_ip"}})
    assert r.status_code == 201 and r.json()["id"] == "CR-001" and r.json()["custom"] is True
    second = client.post("/api/rules/custom", json=BODY).json()
    assert second["id"] == "CR-002" and second["name"] == "Root from outside"
    assert {x["id"] for x in client.get("/api/rules").json() if x["custom"]} == {"CR-001", "CR-002"}
    import_auth(client)
    alerts = client.get("/api/alerts?rule_id=CR-001&limit=100").json()
    assert alerts["total"] >= 1 and all(a["rule_id"] == "CR-001" for a in alerts["items"])


def test_ids_are_reused_after_a_delete_and_limited(client):
    for _ in range(2):
        client.post("/api/rules/custom", json=BODY)
    assert client.delete("/api/rules/custom/CR-001").status_code == 200
    assert client.post("/api/rules/custom", json=BODY).json()["id"] == "CR-001"
    assert client.delete("/api/rules/custom/HZ-001").status_code == 404
    assert client.delete("/api/rules/custom/CR-099").status_code == 404


def test_invalid_rules_are_refused_with_a_reason(client):
    r = client.post("/api/rules/custom", json={**BODY, "params": {"when": {"all": []}}})
    assert r.status_code == 422 and "non-empty" in r.json()["detail"]
    assert client.post("/api/rules/custom", json={**BODY, "name": " "}).status_code == 422
    assert client.post("/api/rules/custom", json={**BODY, "name": "x" * 101}).status_code == 422


def test_replacing_and_patching_a_custom_rule_validates_it(client):
    client.post("/api/rules/custom", json=BODY)
    r = client.put("/api/rules/custom/CR-001", json={**BODY, "name": "Renamed", "severity": "low", "enabled": False})
    assert r.json()["name"] == "Renamed" and r.json()["severity"] == "low" and r.json()["enabled"] is False
    assert client.put("/api/rules/custom/CR-050", json=BODY).status_code == 404
    assert client.patch("/api/rules/CR-001", json={"params": {"threshold": 0}}).status_code == 422
    assert client.patch("/api/rules/CR-001", json={"params": {"threshold": 4}}).json()["params"]["threshold"] == 4


def test_a_disabled_custom_rule_raises_nothing(client):
    client.post("/api/rules/custom", json={**BODY, "enabled": False, "params": {"when": leaf("event_type", "eq", "authentication_failure"), "group_by": "source_ip"}})
    import_auth(client)
    assert client.get("/api/alerts?rule_id=CR-001").json()["total"] == 0


def test_sigma_preview_and_import_through_the_api(client):
    preview = client.post("/api/rules/sigma", json={"text": SIGMA, "save": False})
    assert preview.status_code == 201 and preview.json()["saved"] is False and preview.json()["severity"] == "high"
    assert [r for r in client.get("/api/rules").json() if r["custom"]] == []
    saved = client.post("/api/rules/sigma", json={"text": SIGMA}).json()
    assert saved["saved"] is True and saved["id"] == "CR-001" and saved["name"] == "Admin logons from outside"
    bad = client.post("/api/rules/sigma", json={"text": "title: T\ndetection:\n  s:\n    A|re: x\n  condition: s"})
    assert bad.status_code == 422 and "not supported" in bad.json()["detail"]


# ---- replay ----------------------------------------------------------------------------------------------------
def test_replay_shows_what_a_rule_would_have_flagged_without_saving(client, session, engine):
    import_auth(client)
    alerts_before = client.get("/api/alerts?limit=500").json()["total"]
    r = client.post("/api/rules/replay", json={"rule_id": "HZ-001", "days": 90})
    assert r.status_code == 200
    body = r.json()
    assert body["rule_id"] == "HZ-001" and body["events_scanned"] > 0 and body["would_alert"] >= 1
    assert body["already_alerted"] == body["would_alert"]  # the import already raised these alerts
    assert body["detections"][0].keys() >= {"key", "severity", "occurrences", "first_event", "event_ids", "already_alerted"}
    assert "one batch" in body["note"]
    assert client.get("/api/alerts?limit=500").json()["total"] == alerts_before  # nothing was saved


def test_replay_can_try_other_settings_before_they_are_saved(client):
    import_auth(client)
    strict = client.post("/api/rules/replay", json={"rule_id": "HZ-001", "days": 90, "params": {"threshold": 500, "critical_threshold": 600}}).json()
    default = client.post("/api/rules/replay", json={"rule_id": "HZ-001", "days": 90}).json()
    assert strict["would_alert"] == 0 < default["would_alert"]
    # and the stored rule is unchanged:
    assert next(r for r in client.get("/api/rules").json() if r["id"] == "HZ-001")["params"]["threshold"] != 500


def test_replay_of_a_draft_custom_rule(client):
    import_auth(client)
    draft = {"name": "Draft", "days": 90, "severity": "low", "params": {"when": leaf("event_type", "eq", "unknown_user"), "group_by": "source_ip"}}
    body = client.post("/api/rules/replay", json=draft).json()
    assert body["would_alert"] >= 1 and set(body["by_severity"]) == {"low", "medium", "high", "critical"} and body["by_severity"]["low"] == body["would_alert"]
    assert client.post("/api/rules/replay", json={"days": 7}).status_code == 422
    assert client.post("/api/rules/replay", json={**draft, "params": {"when": {"all": []}}}).status_code == 422


def test_replay_refuses_what_cannot_be_replayed_and_bad_periods(client):
    assert client.post("/api/rules/replay", json={"rule_id": "HZ-008", "days": 7}).status_code == 422
    assert client.post("/api/rules/replay", json={"rule_id": "HZ-001", "days": 0}).status_code == 422
    assert client.post("/api/rules/replay", json={"rule_id": "HZ-001", "days": 91}).status_code == 422
    assert client.post("/api/rules/replay", json={"rule_id": "NOPE", "days": 7}).status_code == 404
