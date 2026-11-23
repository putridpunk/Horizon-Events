# Horizon Events — Design (Milestones 1–4)

Date: 2026-11-23

## Intent and why

Horizon Events is a lightweight SIEM: it imports logs from several sources, normalises them into one event shape, runs rule-based detection, stores events and alerts, and presents them in a dark, professional dashboard.

It is a **portfolio piece**. Success means a reviewer can run one command, see a believable attack story across Linux and Windows logs, read clean modular code, and see a solid test suite and documentation. Effort goes into demo quality, architecture, tests and docs, not production hardening.

## Goals

- End-to-end flow: import → parse → normalise → detect → store → alert → dashboard → report.
- Sources: Linux auth log (sshd/sudo), Linux syslog, Windows Event Log (exported XML/JSON/CSV; no live Windows API), application logs, custom JSON.
- Six detection rules, configurable thresholds and windows.
- Alert lifecycle (Open / Investigating / Resolved) with history and alert→event links.
- REST API, React dashboard (Overview, Events, Alerts, Analytics, Reports), JSON/CSV/HTML reports.
- `docker compose up` runs everything and can seed sample data.
- Pytest unit and integration tests for all critical components.

## Non-goals (milestone 5, deferred)

ML anomaly detection, continuous log tailing, threat-intel enrichment, MITRE mapping, incident grouping. The design leaves seams for them (below) but builds none.

## Anti-goals

- Microservices, queues, or any infrastructure beyond API + frontend containers.
- Detection logic coupled to FastAPI, SQLAlchemy or the frontend.
- A dashboard that looks generic or only works with hand-made data.
- Claiming an alert is a confirmed breach (wording says "suspicious activity").

## Approaches considered

- **A. Flat FastAPI app** — fastest, but mixes DB and business logic; weak as portfolio evidence.
- **B. Modular monolith with service layer** — **chosen by the user**. Pure-Python pipeline, repository layer for DB, thin API.
- **C. Services + message queue** — rejected: needless infrastructure, contradicts "avoid unnecessary dependencies".

## Architecture

Follows the repository layout in the project spec (`backend/app/{collectors,processors,detection,alerts,database,api}`, `frontend/`, `sample_logs/`, `docs/`, `docker-compose.yml`, `requirements.txt`). Additions: `backend/app/services/` (orchestration), `backend/app/database/repositories.py`, `backend/app/reports/`, `backend/app/config.py`.

Dependency direction (no cycles):

```
api → services → {collectors, processors, detection, alerts} → domain types
                       database/repositories ← services
```

- `collectors/*`: read a file/stream and yield raw records (`RawRecord{source, line/obj, origin}`). No parsing of meaning.
- `processors/parser.py`: regex/JSON/XML parsing per format into intermediate fields. `normalizer.py`: maps to the common `Event` dataclass.
- `Event` (pure dataclass): `timestamp, source, event_type, severity, username, source_ip, host, message, raw, metadata`.
- `detection/engine.py`: runs enabled `Rule` objects over a batch of new events. `Rule` interface: `id, name, description, severity, event_types, params, evaluate(new_events, history) -> list[Detection]`. A future ML detector implements the same interface.
- `history` is a read-only `EventHistory` protocol (window queries by type/ip/user/time), implemented by the repository layer. Rules never import SQLAlchemy.
- `alerts/manager.py`: turns `Detection`s into alerts, dedupes within a window (same rule+ip+user updates occurrence count instead of duplicating), manages status transitions and writes `alert_history`.
- `database/`: SQLAlchemy 2.0 models and a session factory driven by `DATABASE_URL` (SQLite default, PostgreSQL-compatible types only). Repositories are the only code issuing queries.
- `api/`: FastAPI routers (`events`, `alerts`, `statistics`, plus `imports`, `rules`, `reports`). Thin: validate, call a service, serialise.

## Data model

Tables as specified: `events`, `alerts`, `detection_rules`, `log_sources`, `alert_history`. Plus `alert_events` (alert↔event many-to-many) for traceability. Indexes: `events(timestamp)`, `events(event_type)`, `events(source_ip)`, `events(username)`, `alerts(status, severity)`. Rule thresholds/windows/enabled live in `detection_rules` (seeded from defaults, editable via API).

## Event types (normalised vocabulary)

`authentication_success`, `authentication_failure`, `unknown_user`, `account_lockout`, `privilege_escalation`, `service_failure`, `service_start`, `generic`. Severity: low / medium / high / critical.

## Detection rules (defaults)

| ID | Rule | Default |
|----|------|---------|
| HZ-001 | Repeated login failures | ≥5 failures per (ip) in 5 min → high; ≥10 → critical |
| HZ-002 | Unusual login hours | successful login outside 08:00–18:00 or on weekends (configurable) → medium |
| HZ-003 | Unknown users | ≥1 attempt for nonexistent account (≥3 per ip → high) |
| HZ-004 | Privilege escalation | sudo/su to root by non-allowlisted user; Windows 4672/4728 → high |
| HZ-005 | Service failures | ≥3 failures per service in 10 min → medium |
| HZ-006 | Account lockouts | any lockout event (Windows 4740, pam_tally) → high |

## Normalisation notes

- Syslog timestamps lack a year: assume the current year, and roll back one year if that makes the timestamp future-dated by more than a day. Stored as naive UTC-assumed ISO; source timezone is a documented limitation.
- Unparseable lines are counted and reported in the import result, never silently dropped, and never crash the import.
- Imports are size-capped and validate content type; parsing never uses `eval` or unsafe XML (use `defusedxml`).

## API surface (summary)

`POST /api/imports` (file + source type), `GET /api/events` (search, filters, pagination), `GET /api/events/{id}`, `GET /api/alerts` (filters), `GET /api/alerts/{id}` (with events and history), `PATCH /api/alerts/{id}` (status, note), `GET /api/statistics/*` (overview, timeseries, top types, top IPs, severity distribution, rule stats), `GET/PATCH /api/rules`, `GET /api/reports?from&to&format=json|csv|html`.

Dashboard polls the API (events feed every few seconds). Real-time push is deferred.

## Frontend

Vite + React + `react-chartjs-2` (Chart.js), React Router, a small fetch service layer. Pages: Overview, Events, Alerts (with detail drawer and status workflow), Analytics, Reports, plus an import control. Dark cyber theme: near-black navy surfaces, one cyan/blue accent, severity colours (critical red, high orange, medium amber, low blue), readable monospace for IPs/raw logs. Pandas is used only where it clearly helps (report/statistics aggregation); otherwise SQL aggregation is used.

## Demo and sample data

`sample_logs/` contains synthetic Linux auth/syslog, Windows events, an app log and custom JSON, scripted to tell a story: SSH brute force from one IP followed by a success, probes of nonexistent users, an after-hours login, a lockout, a sudo escalation, a flapping service. A seed command (`python -m app.seed`) and a compose option import them. No real data or secrets; config via environment variables.

## Testing

Pytest with in-memory SQLite. Unit: each parser/normaliser against sample lines, each rule with threshold edge cases, alert dedup and status transitions. Integration: import file → events/alerts in DB via API TestClient; report generation. Frontend: build must succeed; light component tests only if cheap.

## Docker

`docker-compose.yml`: `backend` (uvicorn, SQLite volume) and `frontend` (built static assets served by nginx, proxying `/api`). PostgreSQL is not added now; the `DATABASE_URL` seam keeps it a config change.

## Decisions I made (not user-chosen)

- Vite + react-chartjs-2 + React Router for the frontend.
- Windows support is for exported event logs (XML/JSON/CSV), not live collection.
- Alert dedup window and the default thresholds above.
- `alert_events` join table and `defusedxml`.
- Polling instead of WebSockets for the feed.
- Naive-timestamp, current-year handling for syslog.

## Left to the builder

Exact column types, file-level module splits, UI component structure and styling details, report HTML template, and test fixture contents, within the constraints above.
