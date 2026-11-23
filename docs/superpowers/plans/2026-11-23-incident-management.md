# Incident Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Group alerts into incidents (automatic correlation by IP or account, manual edits, audit trail) with API, dashboard page and report summary.

**Architecture:** New tables and `IncidentRepository`; a pure-logic `IncidentManager` in `app/incidents/`; an ingestion hook and startup backfill; thin API; React Incidents page.

**Tech Stack:** existing Python/FastAPI/SQLAlchemy/React stack; no new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-23-incident-management-design.md`

## Global Constraints

- Incident code `INC-` plus 6-digit id; statuses OPEN, INVESTIGATING, RESOLVED; transitions OPEN to INVESTIGATING or RESOLVED, INVESTIGATING to RESOLVED or OPEN, RESOLVED to OPEN.
- Correlation window 24 hours of event time (`alert.last_seen` against the incident's `last_activity`); only non-RESOLVED incidents are joined; lowest incident id wins; alerts with neither `source_ip` nor `username` are not grouped.
- An alert belongs to at most one incident. Incident severity is the highest severity among its alerts.
- Every change writes an `incident_history` row.
- `incidents/manager.py` contains no SQL and no framework imports. Run tests with `.venv/Scripts/python.exe -m pytest` from `backend/`.

## Review Focus

- Re-importing a file never creates duplicate incidents or moves alerts between incidents.
- Removing an alert from an incident does not get it re-correlated back on the next import.
- Merging into itself, into a missing incident, or a resolved source/target is rejected or handled with a clear error.
- An alert dedupe-merged into an existing alert refreshes its incident's severity and activity time.
- Empty database: list returns zero items, detail of a missing id is 404.

---

### Task 1: Models, repository and IncidentManager

**Files:**
- Create: `backend/app/incidents/__init__.py`, `backend/app/incidents/manager.py`, `backend/tests/test_incident_manager.py`
- Modify: `backend/app/database/models.py` (`IncidentRow`, `IncidentAlertLink`, `IncidentHistoryRow`), `backend/app/database/repositories.py` (`IncidentRepository`)

**Interfaces:**
- Produces: `IncidentRepository(session)` with `create(**fields)`, `get(id)`, `list(status, severity, limit, offset) -> (rows, total)`, `incident_for_alert(alert_id)`, `alerts_of(incident_id) -> list[AlertRow]`, `candidates(source_ip, username, since, until) -> list[IncidentRow]` (non-RESOLVED incidents with a matching alert and `last_activity` inside the window, ordered by id), `link(incident_id, alert_id, added_by)`, `unlink(alert_id)`, `add_history(incident_id, action, detail=None, from_status=None, to_status=None)`, `history(incident_id)`, `unassigned_alerts() -> list[AlertRow]`.
- Produces: `IncidentManager(repo)` with `correlate(alerts: list[AlertRow]) -> None`, `change_status(id, status: AlertStatus, note=None)`, `set_title(id, title)`, `add_note(id, text)`, `add_alert(id, alert_id)`, `remove_alert(id, alert_id)`, `merge(source_id, into_id)`, `backfill() -> int`. Reuses `InvalidTransition` from `alerts.manager`; raises `LookupError` for missing ids and `ValueError` for invalid merges. `IncidentRow.code` is `INC-######`.

- [ ] **Step 1: Write failing tests** (use `AlertRepository.create` to make alerts directly): `test_new_alert_creates_incident_with_code_and_title`, `test_same_ip_joins_existing_incident`, `test_same_username_joins`, `test_different_keys_do_not_join`, `test_more_than_24h_apart_does_not_join`, `test_resolved_incident_not_joined`, `test_alert_without_ip_or_username_not_grouped`, `test_severity_is_maximum_and_refreshes`, `test_correlate_is_idempotent`, `test_backfill_is_idempotent`, `test_add_alert_moves_between_incidents_and_audits_both`, `test_removed_alert_not_recorrelated`, `test_merge_moves_alerts_and_marks_source`, `test_merge_into_self_or_missing_rejected`, `test_status_transitions_audited_and_invalid_rejected`, `test_note_and_title_audited`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** the full suite → PASS.
- [ ] **Step 5: Commit** `feat: incident model and manager`.

### Task 2: Ingestion hook, startup backfill, API and report

**Files:**
- Create: `backend/app/api/incidents.py`, `backend/tests/test_incident_api.py`
- Modify: `backend/app/services/ingestion.py` (call `correlate` for created and updated alerts), `backend/app/main.py` (router; backfill in lifespan), `backend/app/api/schemas.py` (`incident_out`), `backend/app/reports/generator.py` (`incidents` summary), `backend/tests/test_ingestion.py` or `test_statistics.py` (sample-data incident assertions)

**Interfaces:**
- Consumes: Task 1. Endpoints as in the spec; list items: `id, incident_id (code), title, severity, status, alert_count, created_at, last_activity`; detail adds `alerts` (each `alert_out` plus `intel` from `enrich`), `history`, `ips`, `accounts`, `techniques` (union via `mitre.techniques_for_rule`), `first_activity`.
- Report: `incidents: {total, by_status: {OPEN, INVESTIGATING, RESOLVED}}` for incidents whose `last_activity` is in the period; CSV rows `incident_status`; HTML line.

- [ ] **Step 1: Write failing tests**: `test_import_creates_incidents_fewer_than_alerts` (sample linux auth: incident count less than alert count; the alerts for `192.168.1.15` share one incident), `test_reimport_creates_no_new_incidents`, `test_list_and_filters_and_order`, `test_detail_includes_alerts_history_techniques`, `test_patch_status_title_and_note`, `test_patch_invalid_transition_422_history_unchanged`, `test_add_and_remove_alert`, `test_merge_endpoint_and_errors` (self 422, missing 404), `test_missing_incident_404`, `test_empty_db_list`, `test_report_includes_incidents`, `test_startup_backfill_groups_existing_alerts` (create alerts, call `backfill`, incidents exist).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** the full suite → PASS.
- [ ] **Step 5: Commit** `feat: incident API, ingestion hook and reports`.

### Task 3: Incidents page, docs and executable check

**Files:**
- Create: `frontend/src/pages/Incidents.jsx`, `frontend/src/components/IncidentDrawer.jsx`
- Modify: `frontend/src/services/api.js`, `frontend/src/App.jsx`, `frontend/src/components/Layout.jsx`, `frontend/src/pages/Reports.jsx` (incident counts), `README.md`, `docs/architecture.md`, `docs/api.md`

**Interfaces:**
- Page filters by status and severity, lists incidents (code, title, severity, status, alert count, last activity), opens `IncidentDrawer` (summary, IPs/accounts, technique badges, alerts with `SeverityBadge`/`IntelBadge`, status buttons, note box, remove-alert buttons, audit timeline).

- [ ] **Step 1: Implement** page, drawer, routing, nav link and docs (grouping rules, independence of incident and alert status, audit trail).
- [ ] **Step 2: Verify build**: `npm run build` passes.
- [ ] **Step 3: Rebuild and run the exe**: sample data produces incidents, the brute-force IP's alerts are grouped in one incident, start investigation, add a note and remove an alert, then check the audit timeline in the browser pane; restart the exe on the same data folder and confirm no new incidents appear. Run the full suite.
- [ ] **Step 4: Commit** `feat: incidents page and docs`.
