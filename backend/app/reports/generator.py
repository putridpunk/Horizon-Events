"""Security activity reports in JSON, CSV and HTML."""
from __future__ import annotations

import csv
import io
import json
from collections import Counter
from datetime import datetime
from html import escape

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import AlertRow, EventRow
from app.domain import utcnow
from app.mitre import technique_counts
from app.services import statistics as stats

FORMATS = {"json": "application/json", "csv": "text/csv", "html": "text/html"}


def build_report(session: Session, start: datetime, end: datetime) -> dict:
    ev_ts = list(session.scalars(select(EventRow.timestamp).where(EventRow.timestamp >= start,
                                                                   EventRow.timestamp <= end)))
    al_ts = list(session.scalars(select(AlertRow.last_seen).where(AlertRow.last_seen >= start,
                                                                   AlertRow.last_seen <= end)))
    ev_days, al_days = Counter(t.date().isoformat() for t in ev_ts), Counter(t.date().isoformat() for t in al_ts)
    return {
        "period": {"start": start.isoformat(), "end": end.isoformat()},
        "generated_at": utcnow().isoformat(),
        "total_events": len(ev_ts),
        "total_alerts": len(al_ts),
        "first_event": min(ev_ts).isoformat() if ev_ts else None,
        "last_event": max(ev_ts).isoformat() if ev_ts else None,
        "top_event_types": stats.top_event_types(session, 10, start, end),
        "severity_distribution": stats.alert_severity_distribution(session, start, end),
        "rule_stats": stats.rule_stats(session, start, end),
        "techniques": technique_counts(stats.alerts_by_rule(session, start, end)),
        "daily_activity": [{"date": d, "events": ev_days.get(d, 0), "alerts": al_days.get(d, 0)}
                           for d in sorted(set(ev_days) | set(al_days))],
    }


def render(report: dict, fmt: str) -> tuple[bytes, str]:
    if fmt not in FORMATS:
        raise ValueError(f"Unsupported format: {fmt}")
    if fmt == "json":
        body = json.dumps(report, indent=2)
    elif fmt == "csv":
        body = _csv(report)
    else:
        body = _html(report)
    return body.encode("utf-8"), FORMATS[fmt]


def _csv(r: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["section", "key", "value"])
    w.writerow(["summary", "period_start", r["period"]["start"]])
    w.writerow(["summary", "period_end", r["period"]["end"]])
    w.writerow(["summary", "total_events", r["total_events"]])
    w.writerow(["summary", "total_alerts", r["total_alerts"]])
    for x in r["top_event_types"]:
        w.writerow(["event_type", x["name"], x["count"]])
    for x in r["severity_distribution"]:
        w.writerow(["alert_severity", x["severity"], x["count"]])
    for x in r["rule_stats"]:
        w.writerow(["rule", f'{x["rule_id"]} {x["name"]}', x["alerts"]])
    for x in r["techniques"]:
        w.writerow(["technique", f'{x["id"]} {x["name"]}', x["alerts"]])
    for x in r["daily_activity"]:
        w.writerow(["daily_events", x["date"], x["events"]])
        w.writerow(["daily_alerts", x["date"], x["alerts"]])
    return buf.getvalue()


def _table(headers: list[str], rows: list[list]) -> str:
    head = "".join(f"<th>{escape(str(h))}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{escape(str(c))}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _html(r: dict) -> str:
    sections = [
        ("Event categories", _table(["Type", "Events"], [[x["name"], x["count"]] for x in r["top_event_types"]])),
        ("Alert severity", _table(["Severity", "Alerts"], [[x["severity"], x["count"]] for x in r["severity_distribution"]])),
        ("Detection rules", _table(["Rule", "Name", "Alerts", "Last triggered"],
                                   [[x["rule_id"], x["name"], x["alerts"], x["last_triggered"] or "-"] for x in r["rule_stats"]])),
        ("MITRE ATT&CK techniques", _table(["Technique", "Name", "Tactics", "Alerts"],
                                           [[x["id"], x["name"], ", ".join(x["tactics"]), x["alerts"]] for x in r["techniques"]])),
        ("Daily activity", _table(["Date", "Events", "Alerts"],
                                  [[x["date"], x["events"], x["alerts"]] for x in r["daily_activity"]])),
    ]
    body = "".join(f"<h2>{escape(t)}</h2>{h}" for t, h in sections)
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>Horizon Events report</title><style>"
        "body{font-family:system-ui,sans-serif;background:#0b1220;color:#e5ecf6;margin:2rem auto;max-width:860px}"
        "h1,h2{color:#5ad2ff}table{border-collapse:collapse;width:100%;margin-bottom:1rem}"
        "th,td{border:1px solid #223049;padding:.4rem .6rem;text-align:left}th{background:#111c30}</style></head><body>"
        f"<h1>Horizon Events - Security report</h1><p>Period: {escape(r['period']['start'])} to "
        f"{escape(r['period']['end'])}<br>Generated: {escape(r['generated_at'])}</p>"
        f"<p><b>{r['total_events']}</b> events processed, <b>{r['total_alerts']}</b> alerts generated.</p>{body}"
        "</body></html>")
