# Incident Management (Milestone 5, part 5) — Design

Date: 2026-11-23. Approved in conversation ("automatic, go ahead").

## Intent

Group related alerts into incidents so an analyst investigates one story instead of many alerts: automatic correlation, manual correction, an investigation status, and an audit trail of every change. Completes milestone 5.

## Goals / non-goals

- Goals: incidents with ID `INC-000001`, title, severity (highest alert severity), status (OPEN, INVESTIGATING, RESOLVED), notes and a full audit trail; automatic correlation after every import; manual add, remove, move and merge; an Incidents page; incident data in reports.
- Non-goals: resolving alerts automatically when an incident is resolved (statuses stay independent), user accounts or assignees, cross-incident auto-merging, grouping by anything beyond IP and account.
- Anti-goals: incident noise (alerts with nothing to correlate on do not get incidents); silent changes (every change is audited); an incident implying a confirmed breach (wording says "investigation").

## Design

- Tables: `incidents` (id, code, title, severity, status, created_at, last_activity, updated_at); `incident_alerts` (incident id, alert id, added_by `auto|manual`, added_at; an alert belongs to at most one incident); `incident_history` (incident id, action, detail, from_status, to_status, at). Actions: `created`, `alert_added`, `alert_removed`, `status_changed`, `note`, `merged`, `title_changed`.
- `backend/app/incidents/manager.py` (`IncidentManager(incident_repo)`): `correlate(alerts)` for each processed alert: if already in an incident, refresh that incident's severity and `last_activity`; else, if the alert has a source IP or username, join the lowest-numbered non-RESOLVED incident that contains an alert with the same source IP or the same username and whose `last_activity` is within 24 hours (event time) of the alert's `last_seen`; otherwise create an incident titled from the alert ("Repeated login failures from 192.168.1.15" or "... on account admin"). Alerts with neither IP nor username are not grouped automatically. Manual operations: `change_status`, `set_title`, `add_note`, `add_alert` (moves the alert from another incident, auditing both), `remove_alert` (the alert stays unassigned and is not re-correlated), `merge(source_id, into_id)` (moves all alerts, source is marked RESOLVED with a `merged` entry). Status transitions mirror alerts (OPEN to INVESTIGATING or RESOLVED; INVESTIGATING to RESOLVED or OPEN; RESOLVED to OPEN). `backfill(session)` correlates alerts not yet in any incident, in event-time order (idempotent); it runs at startup.
- Hook: `import_logs` calls `correlate` for every created or updated alert, before the commit.
- Repositories: `IncidentRepository` in `database/repositories.py`; manager has no SQL.
- API: `GET /api/incidents` (filters `status, severity`; ordered by severity then last activity; paging); `GET /api/incidents/{id}` (alerts with their techniques and intel, history, union of IPs, accounts and techniques, first/last activity); `PATCH /api/incidents/{id}` (`status` and/or `title`, with optional `note`); `POST /api/incidents/{id}/notes`; `POST /api/incidents/{id}/alerts` (`alert_id`); `DELETE /api/incidents/{id}/alerts/{alert_id}`; `POST /api/incidents/{id}/merge` (`into`). 404 for missing, 422 for invalid transitions or self-merge. Reports gain an `incidents` summary (total and by status for incidents with activity in the period).
- Frontend: an Incidents page (filters, list) and drawer (summary, alerts with severity/technique badges, status buttons, notes, audit timeline, remove alert); an "Incidents" nav link.

## Testing

Correlation: same IP joins, same account joins, different keys do not, more than 24 hours apart does not, a RESOLVED incident is not joined, alerts without IP or account get no incident, severity is the maximum, re-import does not duplicate or regroup, backfill is idempotent. Manual: add moves between incidents with both audited, remove leaves the alert unassigned and unregrouped, merge moves everything and marks the source, invalid transitions leave history unchanged, notes are audited. API: list, detail, patch, add/remove, merge, 404 and 422 cases. Sample data: the seeded alerts form fewer incidents than alerts and the brute-force IP's alerts share one incident.

## Left to the builder

Incident title wording for edge cases, drawer layout, and the exact detail response field names beyond those listed.
