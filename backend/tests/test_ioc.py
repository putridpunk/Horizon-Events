import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.database.models import IntelEntryRow
from app.intel import ioc
from app.intel.service import enrich
from app.main import app
from app.scanning.defender import Finding
from app.scanning.service import record_detection

SHA = "a" * 64
MD5 = "b" * 32
SHA1 = "c" * 40

STIX = json.dumps({"type": "bundle", "id": "bundle--1", "objects": [
    {"type": "indicator", "pattern": f"[file:hashes.'SHA-256' = '{SHA}']"},
    {"type": "indicator", "pattern": f"[file:hashes.MD5 = '{MD5}' OR file:hashes.'SHA-1' = '{SHA1}']"},
    {"type": "indicator", "pattern": "[domain-name:value = 'Evil.Example.com']"},
    {"type": "indicator", "pattern": "[ipv4-addr:value = '198.51.100.0/24']"},
    {"type": "indicator", "pattern": "[url:value = 'http://bad.example.org/payload.exe']"},
    {"type": "malware", "name": "ignored"},
    {"type": "domain-name", "value": "observed.example.net"},
]})

MISP = json.dumps({"response": [{"Event": {"Attribute": [
    {"type": "ip-dst", "category": "Network activity", "value": "203.0.113.9"},
    {"type": "domain", "category": "Network activity", "value": "c2.example.com"},
    {"type": "filename|sha256", "category": "Payload delivery", "value": f"dropper.exe|{SHA}"},
    {"type": "comment", "category": "Other", "value": "ignored"},
    {"type": "ip-src|port", "category": "Network activity", "value": "1.2.3.4|80"},
], "Object": [{"Attribute": [{"type": "md5", "category": "Payload delivery", "value": MD5}]}]}}]})

TEXT = f"""# my list
198.51.100.77   # a botnet
evil.example.com,note
*.wild.example.com
{SHA}
not an indicator
10.0.0.0/8
"""


def test_a_stix_bundle_is_read():
    f = ioc.parse_indicators(STIX)
    assert f.ips == {"198.51.100.0/24"} and f.domains == {"evil.example.com", "bad.example.org", "observed.example.net"}
    assert f.hashes == {("sha256", SHA), ("md5", MD5), ("sha1", SHA1)}


def test_a_misp_export_is_read_including_objects_and_pairs():
    f = ioc.parse_indicators(MISP)
    assert f.ips == {"203.0.113.9/32"} and f.domains == {"c2.example.com"}
    assert f.hashes == {("sha256", SHA), ("md5", MD5)}


def test_a_plain_list_is_read_and_junk_is_counted():
    f = ioc.parse_indicators(TEXT)
    assert f.ips == {"198.51.100.77/32", "10.0.0.0/8"} and f.domains == {"evil.example.com", "wild.example.com"}
    assert f.hashes == {("sha256", SHA)} and f.skipped == 1


@pytest.mark.parametrize("text,message", [
    ("", "empty"), ("   \n", "empty"), ("just words", "No IP addresses"), ("{not json", "could not be read"),
    ('{"type": "bundle", "objects": []}', "No IP addresses"),
])
def test_unusable_files_say_why(text, message):
    with pytest.raises(ioc.IocError, match=message):
        ioc.parse_indicators(text)


def test_too_many_indicators_are_refused(monkeypatch):
    monkeypatch.setattr(ioc, "MAX_ENTRIES", 2)
    with pytest.raises(ioc.IocError, match="more than"):
        ioc.parse_indicators("1.1.1.1\n2.2.2.2\n3.3.3.3")


def test_importing_stores_entries_and_replaces_a_list_with_the_same_name(session):
    r = ioc.import_list(session, "  Threat   Team ", STIX)
    assert r["feed"] == "user:threat-team" and (r["ips"], r["hashes"], r["domains"]) == (1, 3, 3) and r["replaced"] is False
    r = ioc.import_list(session, "threat team", "9.9.9.9\n")
    assert r["replaced"] is True and session.query(IntelEntryRow).filter_by(feed_id="user:threat-team").count() == 1
    assert ioc.find_matches(session, "evil.example.com") == []  # the old entries are gone


def test_the_number_of_lists_is_limited(session):
    for i in range(ioc.MAX_FEEDS):
        ioc.import_list(session, f"list {i}", "1.1.1.1")
    with pytest.raises(ioc.IocError, match="at most"):
        ioc.import_list(session, "one more", "1.1.1.1")
    ioc.import_list(session, "list 3", "2.2.2.2")  # replacing an existing one is fine


def test_a_list_needs_a_usable_name(session):
    for bad in ("", "   ", "!!!", "x" * 101):
        with pytest.raises(ioc.IocError):
            ioc.import_list(session, bad, "1.1.1.1")


def test_imported_addresses_are_matched_by_the_existing_enrichment(session):
    ioc.import_list(session, "Mine", "198.51.100.0/24")
    hit = enrich(session, "198.51.100.5")
    assert hit["listed"] and hit["feeds"] == [{"id": "user:mine", "name": "Mine"}]
    ioc.delete_list(session, "user:mine")
    assert enrich(session, "198.51.100.5")["listed"] is False


def test_domains_are_found_in_text_including_subdomains(session):
    ioc.import_list(session, "Mine", "evil.example.com\n")
    text = "connection to cdn.static.EVIL.example.com failed; also good.example.org"
    [m] = ioc.find_matches(session, text)
    assert m == {"kind": "domain", "value": "evil.example.com", "feed": "Mine"}
    assert ioc.find_matches(session, "notevil.example.com") == [] and ioc.find_matches(session, "example.com") == []


def test_hashes_are_found_in_text_and_in_the_given_list(session):
    ioc.import_list(session, "Mine", f"{SHA}\n{MD5}\n")
    assert [m["value"] for m in ioc.find_matches(session, f"file {SHA.upper()} seen")] == [SHA]
    assert [m["value"] for m in ioc.find_matches(session, "", [MD5])] == [MD5]
    assert ioc.find_matches(session, "") == []


def test_only_imported_lists_can_be_removed(session):
    with pytest.raises(ioc.IocError, match="Only lists you imported"):
        ioc.delete_list(session, "feodo")
    assert ioc.delete_list(session, "user:none") is False


# ---- API -------------------------------------------------------------------------------------------------------
@pytest.fixture
def client(engine):
    def override():
        with Session(engine, expire_on_commit=False) as s:
            yield s
    app.dependency_overrides[get_session] = override
    yield TestClient(app)
    app.dependency_overrides.clear()


def upload(client, name, content, filename="list.txt"):
    return client.post("/api/intel/import", data={"name": name}, files={"file": (filename, content)})


def test_import_and_remove_through_the_api(client):
    r = upload(client, "Team list", STIX)
    assert r.status_code == 201 and r.json()["hashes"] == 3
    feed = next(f for f in r.json()["feeds"] if f["id"] == "user:team-list")
    assert feed["source"] == "custom" and feed["entries"] == 7 and "imported" in feed["description"]
    assert upload(client, "Bad", "nothing useful here").status_code == 422
    assert client.delete("/api/intel/feeds/feodo").status_code == 422
    assert client.delete("/api/intel/feeds/user:missing").status_code == 404
    assert client.delete("/api/intel/feeds/user:team-list").status_code == 200
    assert all(f["id"] != "user:team-list" for f in client.get("/api/intel/status").json()["feeds"])


def test_oversize_files_are_refused(client, monkeypatch):
    monkeypatch.setattr("app.intel.service.MAX_BYTES", 100)
    assert upload(client, "Big", "1.1.1.1\n" * 100).status_code == 413


def test_a_malware_alert_shows_when_its_hash_is_on_an_imported_list(client, engine):
    upload(client, "Known bad", f"{SHA}\n")
    with Session(engine, expire_on_commit=False) as s:
        alert_id = record_detection(s, Finding("Trojan:Win32/Test", r"C:\t\bad.exe"), SHA)
        s.commit()
    detail = client.get(f"/api/alerts/{alert_id}").json()
    assert [(i["kind"], i["value"], i["feed"]) for i in detail["iocs"]] == [("sha256", SHA, "Known bad")]


def test_alerts_without_matches_have_an_empty_list(client):
    data = (Path(__file__).resolve().parents[2] / "sample_logs" / "linux_auth.log").read_bytes()
    client.post("/api/imports", files={"file": ("a.log", data)}, data={"source_type": "linux_auth"})
    alert = client.get("/api/alerts").json()["items"][0]
    assert client.get(f"/api/alerts/{alert['id']}").json()["iocs"] == []
