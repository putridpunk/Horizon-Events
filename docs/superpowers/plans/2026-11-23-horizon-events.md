# Horizon Events Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build milestones 1–4 of Horizon Events: log import, normalisation, rule-based detection, storage, alerts, REST API, React dashboard, reports, Docker.

**Architecture:** Modular monolith. A pure-Python pipeline (collectors → parser → normalizer → detection engine → alert manager) with no FastAPI/SQLAlchemy imports. A repository layer is the only code that queries the DB. FastAPI routers are thin and call `services/`.

**Tech Stack:** Python 3.11+, FastAPI, SQLAlchemy 2.0, SQLite, defusedxml, pytest, httpx; React + Vite + react-chartjs-2 + React Router; Docker Compose.

**Spec:** `docs/superpowers/specs/2026-11-23-horizon-events-design.md`

## Global Constraints

- Repo layout: `backend/app/{collectors,processors,detection,alerts,database,api}`, `backend/tests/`, `frontend/src/{components,pages,charts,services}`, `sample_logs/`, `docs/`, `docker-compose.yml`, `requirements.txt` (repo root), `README.md`.
- Extra modules allowed: `backend/app/{services,reports}`, `backend/app/config.py`, `backend/app/database/repositories.py`.
- Event vocabulary: `authentication_success, authentication_failure, unknown_user, account_lockout, privilege_escalation, service_failure, service_start, generic`. Severities: `low, medium, high, critical`. Alert statuses: `OPEN, INVESTIGATING, RESOLVED`.
- Alert ID format `ALT-000124` (zero-padded to 6). Rule IDs `HZ-001`..`HZ-006`.
- Tables: `events, alerts, detection_rules, log_sources, alert_history, alert_events`. Indexes on `events(timestamp)`, `events(event_type)`, `events(source_ip)`, `events(username)`, `alerts(status, severity)`.
- DB URL from env `DATABASE_URL`, default `sqlite:///./horizon.db`. PostgreSQL-compatible types only.
- Detection/processing modules must not import `fastapi` or `sqlalchemy`.
- XML parsed only with `defusedxml`. No `eval`. Upload size cap 10 MB.
- Syslog timestamps lack a year: use current year, roll back one year if result is >1 day in the future.
- Only synthetic logs; no secrets in repo; config via env vars.
- Default rules: HZ-001 ≥5 failures/ip/5 min (high), ≥10 (critical); HZ-002 successful login outside 08:00–18:00 or weekend (medium); HZ-003 unknown-user attempt (medium), ≥3 per ip/5 min (high); HZ-004 privilege escalation by non-allowlisted user (high); HZ-005 ≥3 service failures/service/10 min (medium); HZ-006 any lockout (high).
- Dark cyber theme: navy-black surfaces, one cyan accent; severity colours critical red, high orange, medium amber, low blue.

## Review Focus

- Empty file or file with only blank lines imported → 0 events, no crash, import result says so.
- Malformed/binary lines mixed into a log → counted as `skipped`, rest still imported.
- Same file imported twice → no duplicate events (dedupe on hash of source+timestamp+raw) and no duplicate alerts.
- Oversized upload (>10 MB) or wrong source type → HTTP 413 / 422 with a clear message.
- Alert status change to an invalid value or illegal jump → 422, history unchanged.
- Dashboard with empty database → every page renders empty states, no JS errors.

---

### Task 1: Backend scaffold and domain types

**Files:**
- Create: `requirements.txt`, `backend/app/__init__.py`, `backend/app/config.py`, `backend/app/domain.py`, `backend/pytest.ini`, `backend/tests/__init__.py`, `backend/tests/test_domain.py`, `.gitignore`

**Interfaces:**
- Produces: `app.config.Settings` (fields `database_url: str`, `max_upload_bytes: int = 10_485_760`, `work_start: int = 8`, `work_end: int = 18`) and `get_settings() -> Settings`.
- Produces in `app.domain`: `Severity`, `EventType`, `AlertStatus` (str Enums with the vocab above); `@dataclass Event(timestamp: datetime, source: str, event_type: EventType, severity: Severity, message: str, raw: str, username: str|None=None, source_ip: str|None=None, host: str|None=None, service: str|None=None, metadata: dict=field(default_factory=dict))` with `Event.fingerprint() -> str` (sha256 of source|timestamp|raw); `@dataclass Detection(rule_id: str, rule_name: str, severity: Severity, description: str, events: list[Event], source_ip: str|None, username: str|None, occurrences: int, window_minutes: int|None, key: str)`.

- [ ] **Step 1: Write failing tests** in `test_domain.py`: `test_fingerprint_stable_for_equal_events` (same inputs → same hash), `test_fingerprint_differs_when_raw_differs`, `test_settings_default_database_url` (`get_settings().database_url == "sqlite:///./horizon.db"` with env unset, via monkeypatch).
- [ ] **Step 2: Run** `cd backend && python -m pytest -q` → FAIL (import error).
- [ ] **Step 3: Implement** the modules above. `requirements.txt` pins: fastapi, uvicorn[standard], sqlalchemy>=2, pydantic>=2, defusedxml, python-multipart, pandas, pytest, httpx. `pytest.ini` sets `pythonpath = .`.
- [ ] **Step 4: Run** pytest → PASS.
- [ ] **Step 5: Commit** `feat: backend scaffold and domain types`.

### Task 2: Parsers and normalizer

**Files:**
- Create: `backend/app/processors/{__init__,parser,normalizer}.py`, `backend/tests/test_parsers.py`, `backend/tests/test_normalizer.py`

**Interfaces:**
- Produces in `parser`: `parse_linux_auth(line: str, now: datetime) -> dict|None`, `parse_syslog(line, now) -> dict|None`, `parse_windows_record(rec: dict) -> dict|None`, `parse_app_line(line: str) -> dict|None`, `parse_json_record(rec: dict) -> dict|None`. Each returns an intermediate dict with keys `timestamp, host, process, message, raw, plus optional username, source_ip, event_hint` or `None` if unparseable.
- Produces in `normalizer`: `normalize(parsed: dict, source: str) -> Event`. `source` ∈ `linux_auth, linux_syslog, windows, application, json`.

- [ ] **Step 1: Write failing tests** (one per case, using exact lines):
  - `"Nov 23 14:20:31 server sshd[1234]: Failed password for admin from 192.168.1.15 port 22 ssh2"` → `authentication_failure`, medium, username `admin`, ip `192.168.1.15`, timestamp `2026-11-23T14:20:31` with `now=2026-11-23`.
  - `"... Failed password for invalid user ghost from 10.0.0.9 ..."` → `unknown_user`, username `ghost`.
  - `"... Accepted password for alice from 10.0.0.5 ..."` → `authentication_success`, low.
  - `"... sudo: bob : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash"` → `privilege_escalation`, high, username `bob`.
  - `"... pam_tally2 ... user admin (locked)"` or `"account locked"` pattern → `account_lockout`.
  - syslog `"... systemd[1]: nginx.service: Failed with result 'exit-code'."` → `service_failure`, service `nginx`.
  - Windows records (dict form): EventID 4625 → failure; 4624 → success; 4740 → lockout; 4672/4728 → privilege_escalation; 7031 → service_failure.
  - Dec 31 log read on Jan 2 → year rolls back (`test_year_rollover`).
  - Garbage line → `parse_*` returns `None`.
- [ ] **Step 2: Run** `pytest backend/tests/test_parsers.py backend/tests/test_normalizer.py -q` → FAIL.
- [ ] **Step 3: Implement** using precompiled regexes; classification lives in the normalizer (map `event_hint`/message patterns to `EventType` and default severity: failure/unknown_user medium, lockout/escalation/service_failure high-or-medium per type, success low).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: log parsers and normalizer`.

### Task 3: Collectors

**Files:**
- Create: `backend/app/collectors/{__init__,base,linux,windows,json_collector,application}.py`, `backend/tests/test_collectors.py`, small fixtures in `backend/tests/fixtures/`

**Interfaces:**
- Consumes: Task 2 parsers/normalizer.
- Produces: `base.ImportResult(total: int, imported: int, skipped: int)` dataclass; `base.collect(source_type: str, content: bytes, now: datetime|None=None) -> tuple[list[Event], ImportResult]`. Source types: `linux_auth, linux_syslog, windows, application, json`. Unknown type raises `ValueError`. Windows accepts XML (`defusedxml`), JSON list/JSONL, or CSV; JSON accepts array or JSONL. Decoding: utf-8 with `errors="replace"`.

- [ ] **Step 1: Write failing tests**: `test_linux_auth_counts` (3 good + 1 garbage line → imported 3, skipped 1), `test_empty_content_returns_zero`, `test_blank_lines_ignored`, `test_windows_xml_and_csv_and_json`, `test_json_array_and_jsonl`, `test_unknown_source_type_raises`, `test_malicious_xml_rejected` (billion-laughs/entity doc → skipped, no crash), `test_binary_garbage_does_not_crash`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** `collect` dispatch; collectors yield raw records, parse, normalise, tally.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: log collectors`.

### Task 4: Database models, connection, repositories

**Files:**
- Create: `backend/app/database/{__init__,connection,models,repositories}.py`, `backend/tests/conftest.py`, `backend/tests/test_repositories.py`

**Interfaces:**
- Produces: `connection.get_engine()`, `connection.SessionLocal`, `connection.init_db()`, `connection.get_session()` (FastAPI-style generator). Models: `EventRow, AlertRow, DetectionRuleRow, LogSourceRow, AlertHistoryRow, AlertEventLink` per Global Constraints, with `EventRow.fingerprint` unique.
- Produces `repositories.EventRepository(session)`: `add_many(events: list[Event], source_id: int|None) -> list[EventRow]` (skips existing fingerprints, returns only newly inserted), `search(q=None, source=None, event_type=None, severity=None, start=None, end=None, limit=50, offset=0) -> tuple[list[EventRow], int]`, `get(id)`, and the `EventHistory` protocol methods used by rules: `count_in_window(event_type, since, until, source_ip=None, username=None, service=None) -> int`, `events_in_window(...) -> list[Event]`.
- Produces `AlertRepository`, `RuleRepository`, `SourceRepository` with the methods the alert manager/API need (create/get/list-with-filters/update status/append history/link events; list/get/update rules; get-or-create source). Signatures are defined by the tests in Step 1.
- `conftest.py` provides `session` fixture on in-memory SQLite.

- [ ] **Step 1: Write failing tests**: `test_add_many_dedupes_by_fingerprint`, `test_search_filters_and_pagination`, `test_count_in_window_by_ip`, `test_alert_filters_by_severity_and_status`, `test_indexes_exist` (inspect via `sqlalchemy.inspect`), `test_alert_event_link_roundtrip`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** SQLAlchemy 2.0 declarative models and repositories.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: database layer and repositories`.

### Task 5: Detection engine and rules

**Files:**
- Create: `backend/app/detection/{__init__,engine,rules}.py`, `backend/tests/test_rules.py`, `backend/tests/test_engine.py`

**Interfaces:**
- Consumes: `Event`, `Detection`, `EventHistory` protocol (Task 4).
- Produces: `rules.Rule` ABC: attrs `id, name, description, severity, event_types, params: dict`; `evaluate(new_events: list[Event], history: EventHistory) -> list[Detection]`. Classes `RepeatedLoginFailures, UnusualLoginHours, UnknownUsers, PrivilegeEscalation, ServiceFailures, AccountLockouts`; `rules.DEFAULT_RULES: list[dict]` (id, name, description, severity, event_types, params, enabled) used for DB seeding; `rules.build_rule(row_like: dict) -> Rule`.
- Produces: `engine.DetectionEngine(rules: list[Rule])` with `run(new_events, history) -> list[Detection]`. Detection `key` = `f"{rule_id}|{source_ip or ''}|{username or ''}"` (used for dedupe).
- `params` keys: HZ-001 `threshold=5, critical_threshold=10, window_minutes=5`; HZ-002 `work_start=8, work_end=18, weekends=True`; HZ-003 `ip_threshold=3, window_minutes=5`; HZ-004 `allowlist=["root"]`; HZ-005 `threshold=3, window_minutes=10`; HZ-006 none.

- [ ] **Step 1: Write failing tests** (fake in-memory `EventHistory`): `test_hz001_fires_at_5_not_at_4`, `test_hz001_critical_at_10`, `test_hz001_window_excludes_old_events`, `test_hz001_groups_by_ip`, `test_hz002_login_at_23_00_fires_and_at_10_00_does_not`, `test_hz002_weekend_configurable`, `test_hz003_unknown_user_single_fires_medium_and_three_per_ip_high`, `test_hz004_sudo_by_allowlisted_does_not_fire`, `test_hz005_three_failures_same_service`, `test_hz006_lockout_fires`, `test_engine_runs_only_enabled_rules`, `test_rule_params_override_defaults`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** rules and engine. Evaluate in terms of `history.count_in_window`/`events_in_window` so the window includes the just-stored events (callers store before detecting).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: detection engine and rules`.

### Task 6: Alert manager

**Files:**
- Create: `backend/app/alerts/{__init__,manager}.py`, `backend/tests/test_alert_manager.py`

**Interfaces:**
- Consumes: `Detection`, `AlertRepository`.
- Produces: `AlertManager(alert_repo, dedupe_window_minutes: int = 30)` with `process(detections: list[Detection]) -> list[AlertRow]` (creates alert `ALT-######` with status OPEN and history entry, links events; if an OPEN/INVESTIGATING alert with same `key` exists inside the window, updates `occurrences`, escalates severity if higher, links new events, no duplicate), `change_status(alert_id: int, new_status: AlertStatus, note: str|None=None) -> AlertRow`. Legal transitions: OPEN→INVESTIGATING|RESOLVED, INVESTIGATING→RESOLVED|OPEN, RESOLVED→OPEN. Illegal/same-state raises `InvalidTransition(ValueError)`.

- [ ] **Step 1: Write failing tests**: `test_creates_alert_with_formatted_id`, `test_dedupes_same_key_within_window`, `test_new_alert_after_resolved`, `test_severity_escalates_on_merge`, `test_status_change_writes_history`, `test_invalid_transition_raises_and_history_unchanged`, `test_priority_orders_critical_first` (repo list sorted by severity rank then recency).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: alert manager`.

### Task 7: Ingestion service, seeding and sample logs

**Files:**
- Create: `backend/app/services/{__init__,ingestion}.py`, `backend/app/seed.py`, `sample_logs/{linux_auth.log,linux_syslog.log,windows_events.xml,app.log,custom.json}`, `backend/tests/test_ingestion.py`

**Interfaces:**
- Consumes: Tasks 3–6.
- Produces: `ingestion.import_logs(session, source_type: str, filename: str, content: bytes) -> dict` returning `{source_id, total, imported, skipped, duplicates, alerts_created}`. Flow: collect → store (dedupe) → seed rules if table empty → run engine over *newly inserted* events → `AlertManager.process`. `seed.main()` imports every sample file (CLI: `python -m app.seed`).
- Sample logs tell the story: SSH brute force (12 failures from `192.168.1.15` against `admin` within 5 min, then a success), 4 probes of nonexistent users from `203.0.113.7`, an after-hours (23:40) login by `alice`, a Windows 4740 lockout, a `sudo` escalation by `bob`, nginx flapping 4× in 10 min. Use only RFC 5737/private IPs and fake names.

- [ ] **Step 1: Write failing tests**: `test_full_import_generates_expected_alerts` (after importing all sample files, alert rule IDs include HZ-001..HZ-006), `test_importing_same_file_twice_adds_nothing` (duplicates == total, no new alerts), `test_empty_file_import`, `test_mixed_garbage_counts_skipped`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** and write sample logs. **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: ingestion service and sample data`.

### Task 8: Statistics and reports

**Files:**
- Create: `backend/app/services/statistics.py`, `backend/app/reports/{__init__,generator}.py`, `backend/tests/test_statistics.py`, `backend/tests/test_reports.py`

**Interfaces:**
- Produces `statistics`: `overview(session) -> dict(total_events, total_alerts, open_alerts, critical_alerts, high_alerts, sources)`, `events_over_time(session, bucket="hour", start=None, end=None) -> list[{t, count}]`, `top_event_types(session, limit=10)`, `top_source_ips(session, limit=10)`, `alert_severity_distribution(session)`, `rule_stats(session) -> list[{rule_id, name, alerts, last_triggered}]`. Use SQL aggregation (pandas only if clearly simpler).
- Produces `generator.build_report(session, start: datetime, end: datetime) -> dict` (keys: period, total_events, total_alerts, top_event_types, severity_distribution, rule_stats, daily_activity, generated_at) and `render(report: dict, fmt: str) -> tuple[bytes, str]` returning bytes and media type for `json|csv|html`; unknown fmt raises `ValueError`. HTML must escape all values.

- [ ] **Step 1: Write failing tests** on the seeded sample DB: counts match, severity distribution sums to total alerts, `rule_stats` includes all 6 rules, empty DB returns zeros and empty lists, report JSON round-trips, CSV has header row, HTML escapes `<script>` in a rule name.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: statistics and reports`.

### Task 9: REST API

**Files:**
- Create: `backend/app/main.py`, `backend/app/api/{__init__,imports,events,alerts,statistics,rules,reports}.py`, `backend/app/api/schemas.py`, `backend/tests/test_api.py`

**Interfaces:**
- Endpoints: `POST /api/imports` (multipart `file`, form `source_type`), `GET /api/events` (`q, source, event_type, severity, start, end, limit, offset` → `{items, total}`), `GET /api/events/{id}`, `GET /api/alerts` (`severity, status, rule_id, limit, offset`), `GET /api/alerts/{id}` (with linked events and history), `PATCH /api/alerts/{id}` (`{status, note?}`), `GET /api/statistics/{overview|timeseries|event-types|source-ips|severity|rules}`, `GET /api/rules`, `PATCH /api/rules/{rule_id}` (`enabled`, `params`, `severity`), `GET /api/reports?start&end&format=json|csv|html`, `GET /api/health`. CORS allows the frontend origin from env `CORS_ORIGINS`. `main.app` calls `init_db()` on startup.
- Errors: 413 oversize upload, 422 bad source_type / illegal status / bad format, 404 missing id.

- [ ] **Step 1: Write failing tests** with `TestClient` and an overridden `get_session`: `test_import_then_list_events`, `test_import_oversize_413`, `test_import_bad_source_422`, `test_events_filter_by_severity`, `test_alert_detail_includes_events_and_history`, `test_patch_alert_status_and_history`, `test_patch_alert_invalid_status_422`, `test_patch_rule_threshold_changes_detection` (raise HZ-001 threshold, re-import different file, no alert), `test_statistics_empty_db`, `test_report_formats`, `test_health`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** thin routers calling services/repositories. **Step 4: Run** the full backend suite → PASS.
- [ ] **Step 5: Commit** `feat: REST API`.

### Task 10: Frontend scaffold, theme and service layer

**Files:**
- Create: `frontend/{package.json,vite.config.js,index.html}`, `frontend/src/{main.jsx,App.jsx,theme.css}`, `frontend/src/services/api.js`, `frontend/src/components/{Layout,Sidebar,StatCard,SeverityBadge,StatusBadge,EmptyState,DataTable}.jsx`

**Interfaces:**
- Produces `services/api.js`: `getOverview()`, `getTimeseries()`, `getEventTypes()`, `getSourceIps()`, `getSeverity()`, `getRuleStats()`, `listEvents(params)`, `getEvent(id)`, `listAlerts(params)`, `getAlert(id)`, `updateAlert(id, {status, note})`, `listRules()`, `updateRule(id, patch)`, `importLogs(file, sourceType)`, `reportUrl(start, end, format)`. Base URL `/api` (Vite dev proxy to `http://localhost:8000`).
- Routes: `/` Overview, `/events`, `/alerts`, `/analytics`, `/reports`. `theme.css` defines CSS variables per Global Constraints.

- [ ] **Step 1: Scaffold** with Vite + React; deps: `react-router-dom`, `chart.js`, `react-chartjs-2`.
- [ ] **Step 2: Implement** layout, sidebar nav, theme, shared components and `api.js` (fetch wrapper that throws on non-2xx with the server's `detail`).
- [ ] **Step 3: Verify** `cd frontend && npm install && npm run build` succeeds (expected: build completes, no errors).
- [ ] **Step 4: Commit** `feat: frontend scaffold and design system`.

### Task 11: Dashboard pages and charts

**Files:**
- Create: `frontend/src/pages/{Overview,Events,Alerts,Analytics,Reports}.jsx`, `frontend/src/charts/{EventsOverTime,SeverityDoughnut,TopList,RuleBar}.jsx`, `frontend/src/components/{AlertDrawer,EventDetail,ImportButton}.jsx`

**Interfaces:**
- Consumes: `services/api.js` (Task 10).
- Behaviour: Overview shows stat cards (total events, total alerts, critical, high), events-over-time line chart, latest alerts. Events: search box + source/type/severity filters, pagination, polling every 5 s, row click opens `EventDetail` with raw log. Alerts: filters by severity/status, `AlertDrawer` with description, occurrences, linked events, history timeline, status buttons (Investigating/Resolved/Reopen) and note field. Analytics: events over time, top event types, top source IPs, severity doughnut, rule statistics bar. Reports: date range, format select, download link. Every page shows `EmptyState` on empty data and an error banner on API failure. `ImportButton` in the header uploads a file with a source-type select and shows the import result.

- [ ] **Step 1: Implement** pages and charts.
- [ ] **Step 2: Verify build**: `npm run build` passes.
- [ ] **Step 3: Verify in browser**: start backend (`uvicorn app.main:app` from `backend/`) and `npm run dev`; with an empty DB all pages show empty states with no console errors; run `python -m app.seed`, reload: Overview shows non-zero stats, Alerts shows HZ-001 alert as critical, changing its status to Investigating updates the history timeline. Report in the final summary exactly what was observed.
- [ ] **Step 4: Commit** `feat: dashboard pages and charts`.

### Task 12: Docker, README and docs

**Files:**
- Create: `backend/Dockerfile`, `frontend/Dockerfile`, `frontend/nginx.conf`, `docker-compose.yml`, `.dockerignore`, `README.md`, `docs/architecture.md`, `docs/detection-rules.md`, `docs/api.md`

**Interfaces:**
- `docker compose up --build` serves the UI at `http://localhost:8080` (nginx proxying `/api` to backend at 8000); SQLite on a named volume; env `SEED_ON_START=true` runs `python -m app.seed` once if the events table is empty.

- [ ] **Step 1: Write** Dockerfiles, nginx config and compose file.
- [ ] **Step 2: Verify** `docker compose up --build -d` then `curl http://localhost:8080/api/health` returns `{"status":"ok"}` and `/api/alerts` shows seeded alerts (if Docker is unavailable, say so explicitly rather than claim verification).
- [ ] **Step 3: Write docs**: README with overview, architecture diagram (ASCII from the spec), quick start (Docker and local), sample-log walkthrough, screenshots placeholder section, testing instructions, roadmap listing milestone 5. `docs/detection-rules.md` documents each rule's params.
- [ ] **Step 4: Run** full `pytest` one last time → PASS.
- [ ] **Step 5: Commit** `feat: docker deployment and documentation`.
