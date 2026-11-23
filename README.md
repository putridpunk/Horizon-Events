# HORIZON EVENTS

**Security Information and Event Management** · *Turning security events into actionable intelligence.*

[![CI](https://github.com/putridpunk/Horizon-Events/actions/workflows/ci.yml/badge.svg)](https://github.com/putridpunk/Horizon-Events/actions/workflows/ci.yml)

Horizon Events is a lightweight SIEM. It imports logs from Linux and Windows systems and applications, normalises them into one event format, runs configurable detection rules, raises alerts with a full status history, and presents everything in a dark, interactive dashboard. Reports export to JSON, CSV and HTML.

Built with Python, FastAPI, SQLAlchemy (SQLite), React, Chart.js and Docker. All bundled data is synthetic.

## Screenshots

All data below is synthetic, produced by the bundled sample logs.

**Overview**: counts, events over time, the latest alerts and live monitoring of a watch folder.

![Overview dashboard](docs/screenshots/overview.png)

**Alert detail**: MITRE ATT&CK techniques, the investigation workflow, history and the events behind the alert. The "Known malicious" badge comes from a threat feed, matched locally.

![Alert detail drawer](docs/screenshots/alert-drawer.png)

**Incident**: related alerts grouped by shared IP or account, with an audit trail.

![Incident detail drawer](docs/screenshots/incident-drawer.png)

**Analytics**: distributions, MITRE ATT&CK coverage, the anomaly model (HZ-007), threat feeds and per-rule statistics.

![Analytics](docs/screenshots/analytics.png)

<details>
<summary>More: event feed and reports</summary>

![Event monitoring](docs/screenshots/events.png)

![Reports](docs/screenshots/reports.png)

</details>

## Architecture

```
LOG SOURCES -> COLLECTION -> NORMALISATION -> DETECTION ENGINE -> DATABASE -> ALERT MANAGEMENT -> DASHBOARD
```

- `collectors/` read Linux auth/syslog, Windows events (XML/JSON/CSV exports), application logs and custom JSON.
- `processors/` parse each format and normalise it to a common `Event`.
- `detection/` is a pure-Python, rule-based engine. It has no FastAPI or database imports and reads history through a small `EventHistory` protocol, so a future ML detector can implement the same `Rule` interface.
- `alerts/` creates, de-duplicates and tracks alerts (Open, Investigating, Resolved) with history.
- `database/` holds SQLAlchemy models and repositories, the only code that issues queries. SQLite today; `DATABASE_URL` is the seam for PostgreSQL.
- `api/` are thin FastAPI routers over `services/`.

See [docs/architecture.md](docs/architecture.md), [docs/detection-rules.md](docs/detection-rules.md) and [docs/api.md](docs/api.md).

## Quick start (Docker)

```bash
docker compose up --build
```

Open http://localhost:8080. The sample logs are imported automatically on first start (set `SEED_ON_START=false` to disable).

## Quick start (local)

Backend (Python 3.11+):

```bash
python -m venv .venv
.venv/Scripts/activate        # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
cd backend
python -m app.seed            # optional: import the sample logs
uvicorn app.main:app --reload
```

Frontend (Node 20+):

```bash
cd frontend
npm install
npm run dev                   # http://localhost:5173, proxies /api to localhost:8000
```

## PostgreSQL

SQLite is the default. To run on PostgreSQL, either set `DATABASE_URL=postgresql+psycopg://user:password@host:5432/dbname` for a local run, or use the compose override:

```bash
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up --build
```

The override starts PostgreSQL 16 (not published to the host) and points the backend at it; set `POSTGRES_PASSWORD` for anything beyond local use. The whole test suite also runs against PostgreSQL: set `HORIZON_TEST_DATABASE_URL` to a throwaway database (the schema is recreated for every test) and run `python -m pytest`. CI runs the suite on both databases.

## Windows executable

`dist\HorizonEvents.exe` is a single-file build that runs the API and dashboard on `http://127.0.0.1:8000` (or a free port if that one is taken) and opens your browser. On first run it imports the sample logs; data lives in `%LOCALAPPDATA%\HorizonEvents\horizon.db`. Set `HORIZON_SEED=false` to start empty. Close the console window to stop it.

To rebuild it (needs the frontend built and the `.venv` set up):

```powershell
pip install -r requirements-build.txt
cd frontend; npm install; npm run build; cd ..
powershell -File scripts\build-exe.ps1
```

## Live monitoring

Set `HORIZON_WATCH_DIR` (the executable defaults to `%LOCALAPPDATA%\HorizonEvents\watch`; Docker mounts `./watch`) and Horizon Events ingests new log lines continuously. The **subfolder name selects the parser**:

```
watch/
  linux_auth/auth.log      linux_syslog/syslog.log     application/app.log
  windows/events.jsonl     json/custom.jsonl
```

Append lines (for example with `Add-Content` or a log shipper) and events, alerts and the dashboard update within a few seconds. Only complete lines are read, files that shrink are re-read from the start, and re-reading a file never creates duplicate events. Limits: only line-oriented files can be tailed (Windows logs as JSON Lines; XML, CSV and JSON arrays are imported manually), only direct children of the known subfolders are read, and symlinks are ignored. The Overview page has a Live monitoring card with Pause and Resume.

## Threat intelligence

Alerts show a **Known malicious** badge when their source IP is on a threat feed. Matching happens locally against downloaded lists, so no IP from your logs is ever sent anywhere. The only network action is the **Refresh feeds** button on the Analytics page, which downloads:

- [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/blocklist/) botnet C2 IPs (CC0), and
- [Spamhaus DROP](https://www.spamhaus.org/drop/) netblocks (free use under Spamhaus's terms; fetched at most once an hour, which the app enforces).

Private and loopback addresses are never checked. A small **synthetic demo feed** (clearly labelled, covering the reserved test addresses used in `sample_logs/`) is loaded with the sample data so the badge shows offline; it is not real intelligence. Per-IP lookup services such as AbuseIPDB are not used because they would send your log data to a third party.

## Incidents

Related alerts are grouped into **incidents** automatically, so you investigate one story instead of many alerts. A new alert joins the lowest-numbered open incident that has an alert with the same source IP or the same account, with activity within 24 hours; otherwise it opens a new incident. Alerts with neither an IP nor an account are not grouped. Incident severity is the highest of its alerts.

On the **Incidents** page you can start an investigation, resolve or reopen an incident, add notes, rename it, remove an alert (it will not be regrouped), or merge incidents. Every change is recorded in the incident's audit trail. An incident's status is separate from its alerts' statuses: resolving an incident does not resolve its alerts. An incident means "investigate these together", not that a breach is confirmed.

## What the sample data demonstrates

`sample_logs/` tells a small story across sources:

| Activity | Rule |
| --- | --- |
| 12 failed SSH logins for `admin` from `192.168.1.15`, then a success | HZ-001 (critical) |
| An after-hours login by `alice` at 23:40 | HZ-002 |
| Four attempts against nonexistent accounts from `203.0.113.7` | HZ-003 |
| `sudo` to root by `bob`; a group change by `tmp_contractor` | HZ-004 |
| `nginx` failing four times; the Windows Spooler service failing | HZ-005 |
| Account lockouts on Linux (`admin`) and Windows (`jsmith`) | HZ-006 |
| A slow password spray (3 attempts an hour, different usernames) from `198.51.100.77` | HZ-007 (ML) |

You can also import your own files from the dashboard's **Import logs** button (choose the matching source type). Re-importing a file does not create duplicates.

## Testing

```bash
cd backend
python -m pytest
```

The suite covers the parsers, collectors, rules, alert manager, repositories, ingestion, statistics, reports and the API.

Frontend tests use [Vitest](https://vitest.dev) and React Testing Library with the API mocked:

```bash
cd frontend
npm test
```

They cover the API client and polling hook, the alert and incident drawers (status workflows, notes, merging, error messages), the list pages and their filters, the live-monitoring, threat-feed and anomaly-model cards, report date handling, and the empty-database screens. The Chart.js charts are stubbed because jsdom has no canvas.

## Security

The API has no login, so Horizon Events is built to be used from the machine it runs on: the executable and the Docker setup listen on `127.0.0.1` only, and the server refuses requests with an unknown `Host` (DNS rebinding) or a foreign `Origin` on state-changing calls (cross-site forgery). Read [docs/security.md](docs/security.md) for what is and is not protected and how to expose it safely behind an authenticating proxy (`HORIZON_BIND`, `HORIZON_ALLOWED_HOSTS`).

## Limitations

- Syslog lines carry no year or timezone; Horizon Events assumes the current year and treats times as UTC.
- Windows support is for exported event logs, not live collection.
- The dashboard polls (every 5-10 seconds) instead of using a push channel.
- Alerts flag *suspicious activity*, not confirmed breaches.

## Roadmap

Done in milestone 5 so far: ML anomaly detection (rule HZ-007, Isolation Forest over per-IP hourly activity; see [docs/detection-rules.md](docs/detection-rules.md)). MITRE ATT&CK mapping (rules and alerts tagged with techniques, coverage panel, report section). Real-time monitoring (a watch folder is tailed continuously; see below). Threat intelligence enrichment (blocklist feeds matched locally; see below). Incident management (alerts grouped into incidents; see below). Milestone 5 is complete.

## Licence

Released under the [MIT Licence](LICENSE). The sample logs are synthetic. Threat feed data downloaded at runtime stays under its providers' terms (abuse.ch Feodo Tracker is CC0; Spamhaus DROP has its own terms of use).
