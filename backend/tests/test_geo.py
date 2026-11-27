from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database.connection import get_session
from app.database.repositories import EventRepository
from app.detection.geo_rules import ImpossibleTravel, NewCountryLogin
from app.domain import EventType, Severity
from app.geo import settings as geo_settings
from app.geo.locator import GeoError, GeoLocator, Location, haversine_km, locate, parse_record, set_locator
from app.main import app
from tests.conftest import make_event

LISBON = {"country": {"iso_code": "PT", "names": {"en": "Portugal"}}, "city": {"names": {"en": "Lisbon"}},
          "location": {"latitude": 38.72, "longitude": -9.14}}
TOKYO = {"country": {"iso_code": "JP", "names": {"en": "Japan"}}, "city": {"names": {"en": "Tokyo"}},
         "location": {"latitude": 35.68, "longitude": 139.69}}
PORTO = {"country": {"iso_code": "PT", "names": {"en": "Portugal"}}, "city": {"names": {"en": "Porto"}},
         "location": {"latitude": 41.15, "longitude": -8.61}}
SPAIN_ONLY = {"country": {"iso_code": "ES", "names": {"en": "Spain"}}}

RECORDS = {"8.8.1.1": LISBON, "8.8.2.2": TOKYO, "8.8.3.3": PORTO, "8.8.4.4": SPAIN_ONLY, "8.8.5.5": SPAIN_ONLY,
           "9.9.9.9": {"city": {"names": {"fr": "Paris"}}}, "7.7.7.7": {}}


class FakeReader:
    def __init__(self, records=RECORDS):
        self.records, self.closed = records, False

    def get(self, ip):
        return self.records.get(ip)

    def close(self):
        self.closed = True


@pytest.fixture
def locator():
    loc = GeoLocator(FakeReader(), {"type": "Fake-City", "built": 1})
    set_locator(loc)
    yield loc
    set_locator(None)


# ---- the locator -----------------------------------------------------------------------------------------------
def test_records_become_locations(locator):
    place = locator.lookup("8.8.1.1")
    assert (place.country_code, place.country, place.city, place.has_coordinates) == ("PT", "Portugal", "Lisbon", True)
    assert place.label() == "Lisbon, Portugal" and Location().label() == "an unknown place"
    assert locator.lookup("8.8.4.4").has_coordinates is False and locator.lookup("8.8.4.4").label() == "Spain"
    assert parse_record({"city": {"names": {"fr": "Paris"}}}) is None  # no country or coordinates: nothing useful
    assert parse_record(None) is None and parse_record({"registered_country": {"iso_code": "DE"}}).country_code == "DE"


@pytest.mark.parametrize("ip", [None, "", "not an ip", "10.0.0.1", "192.168.1.1", "127.0.0.1", "203.0.113.7", "8.8.9.9", "7.7.7.7"])
def test_private_invalid_and_unknown_addresses_have_no_location(locator, ip):
    assert locator.lookup(ip) is None


def test_lookups_are_cached(locator):
    calls = []
    original = locator._reader.get
    locator._reader.get = lambda ip: calls.append(ip) or original(ip)
    locator.lookup("8.8.1.1"), locator.lookup("8.8.1.1")
    assert calls == ["8.8.1.1"]


def test_distance():
    assert 11_000 < haversine_km(Location(latitude=38.72, longitude=-9.14), Location(latitude=35.68, longitude=139.69)) < 12_000
    assert haversine_km(Location(latitude=1, longitude=1), Location(latitude=1, longitude=1)) == 0


@pytest.mark.parametrize("path,message", [
    ("relative/file.mmdb", "full path"), ("C:/data/file.txt", "full path"), ("C:/definitely/missing/db.mmdb", "not found")])
def test_bad_database_paths_are_explained(path, message):
    with pytest.raises(GeoError, match=message):
        GeoLocator.open(path)


def test_a_file_that_is_not_a_database_is_refused(tmp_path):
    junk = tmp_path / "junk.mmdb"
    junk.write_bytes(b"not a database at all" * 10)
    with pytest.raises(GeoError, match="not a location database"):
        GeoLocator.open(str(junk))


def test_replacing_the_locator_closes_the_old_one():
    first = GeoLocator(FakeReader())
    set_locator(first)
    set_locator(GeoLocator(FakeReader()))
    assert first._reader.closed
    set_locator(None)


# ---- the rules -------------------------------------------------------------------------------------------------
def login(session, ip, ts, user="alice", raw=None, etype=EventType.authentication_success):
    [e] = EventRepository(session).add_many([make_event(etype, ts, ip, user, raw=raw or f"{ip}-{ts}-{user}", severity=Severity.low)])
    return e


def test_the_rules_stay_silent_without_a_database(session):
    set_locator(None)
    e = login(session, "8.8.2.2", "2026-11-23T10:00:00")
    assert NewCountryLogin().evaluate([e], EventRepository(session)) == []
    assert ImpossibleTravel().evaluate([e], EventRepository(session)) == []


def test_a_sign_in_from_a_new_country_is_flagged_once(session, locator):
    for i, ts in enumerate(["2026-11-01T09:00:00", "2026-11-02T09:00:00"]):
        login(session, "8.8.1.1", ts)  # Portugal, twice
    first = login(session, "8.8.2.2", "2026-11-20T09:00:00")  # Japan
    again = login(session, "8.8.2.2", "2026-11-20T11:00:00", raw="again")
    repo = EventRepository(session)
    [d] = NewCountryLogin().evaluate([first, again], repo)
    assert d.rule_id == "HZ-018" and d.username == "alice" and d.source_ip == "8.8.2.2" and d.severity is Severity.medium
    assert d.occurrences == 1 and "Tokyo, Japan" in d.description
    # later, the country is known: no alert for the second sign-in
    assert NewCountryLogin().evaluate([again], repo) == []


def test_the_first_ever_sign_in_and_known_countries_do_not_alert(session, locator):
    only = login(session, "8.8.2.2", "2026-11-20T09:00:00", user="bob")
    assert NewCountryLogin().evaluate([only], EventRepository(session)) == []  # nothing to compare with
    login(session, "8.8.1.1", "2026-11-01T09:00:00")
    home = login(session, "8.8.3.3", "2026-11-20T09:00:00")  # Porto: same country as Lisbon
    assert NewCountryLogin().evaluate([home], EventRepository(session)) == []


def test_old_history_and_ignored_countries_are_respected(session, locator):
    login(session, "8.8.1.1", "2026-06-01T09:00:00")  # more than 90 days before
    new = login(session, "8.8.2.2", "2026-11-20T09:00:00")
    assert NewCountryLogin().evaluate([new], EventRepository(session)) == []  # no history inside the window
    login(session, "8.8.1.1", "2026-11-19T09:00:00", raw="recent")
    assert len(NewCountryLogin().evaluate([new], EventRepository(session))) == 1
    assert NewCountryLogin(params={"ignore_countries": ["jp"]}).evaluate([new], EventRepository(session)) == []
    assert NewCountryLogin(params={"min_history": 2}).evaluate([new], EventRepository(session)) == []


def test_other_event_types_and_private_addresses_are_ignored(session, locator):
    login(session, "8.8.1.1", "2026-11-19T09:00:00")
    failure = login(session, "8.8.2.2", "2026-11-20T09:00:00", etype=EventType.authentication_failure)
    private = login(session, "10.0.0.5", "2026-11-20T10:00:00", raw="p")
    assert NewCountryLogin().evaluate([failure, private], EventRepository(session)) == []


def test_impossible_travel_uses_distance_and_speed(session, locator):
    a = login(session, "8.8.1.1", "2026-11-23T10:00:00")  # Lisbon
    b = login(session, "8.8.2.2", "2026-11-23T10:40:00")  # Tokyo 40 minutes later
    [d] = ImpossibleTravel().evaluate([b], EventRepository(session))
    assert d.rule_id == "HZ-019" and d.severity is Severity.high and d.occurrences == 2
    assert d.source_ip == "8.8.2.2" and "Lisbon" in d.description and "Tokyo" in d.description and "40 minutes" in d.description
    assert "km apart" in d.description
    # the same trip over a day is possible
    far = login(session, "8.8.2.2", "2026-11-24T22:00:00", raw="much later")
    assert ImpossibleTravel().evaluate([far], EventRepository(session)) == []
    assert a.id != b.id


def test_nearby_cities_are_not_impossible_travel(session, locator):
    login(session, "8.8.1.1", "2026-11-23T10:00:00")
    porto = login(session, "8.8.3.3", "2026-11-23T10:05:00")  # ~275 km in 5 minutes, but under the 500 km floor
    assert ImpossibleTravel().evaluate([porto], EventRepository(session)) == []


def test_without_coordinates_a_quick_country_change_is_flagged(session, locator):
    login(session, "8.8.4.4", "2026-11-23T10:00:00")  # Spain, no coordinates
    quick = login(session, "8.8.1.1", "2026-11-23T10:20:00")  # Portugal 20 minutes later
    slow = login(session, "8.8.5.5", "2026-11-23T14:00:00", raw="slow")
    repo = EventRepository(session)
    [d] = ImpossibleTravel().evaluate([quick], repo)
    assert "apart" not in d.description
    assert ImpossibleTravel().evaluate([slow], repo) == []  # Spain again: same country as before


def test_travel_is_judged_per_account_and_the_window_is_limited(session, locator):
    login(session, "8.8.1.1", "2026-11-23T10:00:00", user="alice")
    other = login(session, "8.8.2.2", "2026-11-23T10:10:00", user="bob")
    assert ImpossibleTravel().evaluate([other], EventRepository(session)) == []
    login(session, "8.8.1.1", "2026-11-20T10:00:00", user="carol")
    old = login(session, "8.8.2.2", "2026-11-23T10:10:00", user="carol")
    assert ImpossibleTravel().evaluate([old], EventRepository(session)) == []  # 3 days: outside the 24 h window


# ---- API and settings ------------------------------------------------------------------------------------------
@pytest.fixture
def client(engine):
    def override():
        with Session(engine, expire_on_commit=False) as s:
            yield s
    app.dependency_overrides[get_session] = override
    yield TestClient(app)
    app.dependency_overrides.clear()
    set_locator(None)


def test_the_database_is_chosen_remembered_and_cleared(client, monkeypatch, tmp_path):
    assert client.get("/api/geoip").json()["configured"] is False
    fake = tmp_path / "db.mmdb"
    fake.write_bytes(b"x")
    monkeypatch.setattr(GeoLocator, "open", classmethod(lambda cls, path: GeoLocator(FakeReader(), {"type": "Fake", "built": 5})))
    r = client.put("/api/geoip", json={"path": str(fake)})
    assert r.status_code == 200 and r.json()["configured"] is True and r.json()["path"] == str(fake)
    assert r.json()["database"] == {"type": "Fake", "built": 5} and locate("8.8.1.1").city == "Lisbon"
    cleared = client.put("/api/geoip", json={"path": None}).json()
    assert cleared["configured"] is False and cleared["path"] is None and locate("8.8.1.1") is None


def test_a_bad_database_is_refused_and_the_old_one_stays(client, monkeypatch):
    set_locator(GeoLocator(FakeReader()))
    r = client.put("/api/geoip", json={"path": "C:/definitely/missing/db.mmdb"})
    assert r.status_code == 422 and "not found" in r.json()["detail"]
    assert locate("8.8.1.1") is not None


def test_start_up_loading_never_raises(session, monkeypatch):
    monkeypatch.setenv("HORIZON_GEOIP_DB", "C:/definitely/missing/db.mmdb")
    assert "not found" in geo_settings.load_on_start(session)
    monkeypatch.delenv("HORIZON_GEOIP_DB")
    assert geo_settings.load_on_start(session) is None


def test_an_alert_shows_where_its_address_is(client, locator):
    data = (Path(__file__).resolve().parents[2] / "sample_logs" / "linux_auth.log").read_bytes()
    client.post("/api/imports", files={"file": ("a.log", data)}, data={"source_type": "linux_auth"})
    alert = client.get("/api/alerts").json()["items"][0]
    detail = client.get(f"/api/alerts/{alert['id']}").json()
    assert "geo" in detail and detail["geo"] is None  # the sample addresses are private or documentation ranges
