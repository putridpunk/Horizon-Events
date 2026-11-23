# HORIZON EVENTS

**Security Information and Event Management** · *Turning security events into actionable intelligence.*

Horizon Events is a lightweight SIEM. It imports logs from Linux and Windows systems and applications, normalises them into one event format, runs configurable detection rules, raises alerts with a full status history, and presents everything in a dark, interactive dashboard. Reports export to JSON, CSV and HTML.

Built with Python, FastAPI, SQLAlchemy (SQLite), React, Chart.js and Docker. All bundled data is synthetic.

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

## Windows executable

`dist\HorizonEvents.exe` is a single-file build that runs the API and dashboard on `http://127.0.0.1:8000` (or a free port if that one is taken) and opens your browser. On first run it imports the sample logs; data lives in `%LOCALAPPDATA%\HorizonEvents\horizon.db`. Set `HORIZON_SEED=false` to start empty. Close the console window to stop it.

To rebuild it (needs the frontend built and the `.venv` set up):

```powershell
pip install -r requirements-build.txt
cd frontend; npm install; npm run build; cd ..
powershell -File scripts\build-exe.ps1
```

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

## Limitations

- Syslog lines carry no year or timezone; Horizon Events assumes the current year and treats times as UTC.
- Windows support is for exported event logs, not live collection.
- The dashboard polls (every 5-10 seconds) instead of using a push channel.
- Alerts flag *suspicious activity*, not confirmed breaches.

## Roadmap

Done in milestone 5 so far: ML anomaly detection (rule HZ-007, Isolation Forest over per-IP hourly activity; see [docs/detection-rules.md](docs/detection-rules.md)). Still planned: MITRE ATT&CK mapping, continuous log tailing, threat-intelligence enrichment and incident grouping.
