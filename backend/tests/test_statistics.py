import json
from datetime import datetime
from pathlib import Path

import pytest

from app.database.models import DetectionRuleRow
from app.reports.generator import build_report, render
from app.seed import seed
from app.services import statistics as st

SAMPLES = Path(__file__).resolve().parents[2] / "sample_logs"
NOW = datetime(2026, 11, 23, 23, 59, 0)
START, END = datetime(2026, 11, 1), datetime(2026, 12, 1)


@pytest.fixture
def seeded(session):
    seed(session, SAMPLES, NOW)
    return session


def test_overview_and_distribution(seeded):
    o = st.overview(seeded)
    assert o["total_events"] > 40 and o["total_alerts"] >= 6 and o["critical_alerts"] >= 1 and o["sources"] == 6
    assert sum(x["count"] for x in st.alert_severity_distribution(seeded)) == o["total_alerts"]


def test_rule_stats_include_all_rules(seeded):
    rs = st.rule_stats(seeded)
    assert [r["rule_id"] for r in rs] == [f"HZ-{i:03d}" for i in range(1, 20)]
    assert all(r["alerts"] >= 1 for r in rs if r["rule_id"] not in ("HZ-007", "HZ-008", "HZ-009", "HZ-010", "HZ-011", "HZ-012", "HZ-013", "HZ-014", "HZ-015", "HZ-016", "HZ-017", "HZ-018", "HZ-019"))  # HZ-007 needs a trained model; HZ-008 comes from file scans


def test_top_lists_and_timeseries(seeded):
    assert st.top_source_ips(seeded)[0]["name"] == "192.168.1.15"
    assert st.top_event_types(seeded)[0]["name"] == "authentication_failure"
    series = st.events_over_time(seeded, "day")
    assert series == [{"t": "2026-11-23T00:00:00", "count": st.overview(seeded)["total_events"]}]
    with pytest.raises(ValueError):
        st.events_over_time(seeded, "year")


def test_empty_db_returns_zeros(session):
    assert st.overview(session)["total_events"] == 0
    assert st.events_over_time(session) == [] and st.top_source_ips(session) == []
    assert [x["count"] for x in st.alert_severity_distribution(session)] == [0, 0, 0, 0]
    r = build_report(session, START, END)
    assert r["total_events"] == 0 and r["daily_activity"] == []


def test_report_formats(seeded):
    r = build_report(seeded, START, END)
    body, mt = render(r, "json")
    assert mt == "application/json" and json.loads(body)["total_events"] == r["total_events"] > 0
    body, mt = render(r, "csv")
    assert body.decode().splitlines()[0] == "section,key,value"
    body, mt = render(r, "html")
    assert mt == "text/html" and b"Security report" in body
    with pytest.raises(ValueError):
        render(r, "pdf")


def test_report_period_filters(seeded):
    assert build_report(seeded, datetime(2025, 1, 1), datetime(2025, 2, 1))["total_events"] == 0


def test_html_escapes_values(seeded):
    seeded.get(DetectionRuleRow, "HZ-001").name = "<script>alert(1)</script>"
    body, _ = render(build_report(seeded, START, END), "html")
    assert b"<script>alert(1)</script>" not in body and b"&lt;script&gt;" in body
