# REST API

Interactive documentation is served at `/docs` when the backend runs.

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/imports` | Multipart upload: `file`, `source_type` (`linux_auth`, `linux_syslog`, `windows`, `application`, `json`). 413 above 10 MB, 422 for an unknown type. |
| GET | `/api/events` | Filters `q, source, event_type, severity, start, end`; pagination `limit, offset`. Returns `{items, total}`. |
| GET | `/api/events/{id}` | One event including the raw log line. |
| GET | `/api/alerts` | Filters `severity, status, rule_id`; ordered by severity, then recency. |
| GET | `/api/alerts/{id}` | Alert with linked events and status history. |
| PATCH | `/api/alerts/{id}` | Body `{status, note?}`. 422 for an invalid status or transition. |
| GET | `/api/statistics/{overview,timeseries,event-types,source-ips,severity,rules}` | Dashboard aggregates. |
| GET / PATCH | `/api/rules`, `/api/rules/{id}` | Read and tune detection rules. |
| GET | `/api/reports` | `start`, `end`, `format=json\|csv\|html`. |
| GET | `/api/ml/status` | Anomaly model status: `trained`, `trained_at`, `windows`, `source`, `features`. |
| POST | `/api/ml/train` | Body `{source: "synthetic" \| "database"}`. 422 when the database has too little data. |
| GET | `/api/mitre/techniques` | The built-in ATT&CK technique table. |
| GET | `/api/statistics/mitre` | `{tactics, techniques}`: alert counts per tactic and technique. Alerts and rules also carry a `techniques` list. |
| GET | `/api/watcher/status` | Live monitoring state: `enabled`, `running`, `paused`, `directory`, per-file counters. `{enabled: false}` when no watch folder is configured. |
| POST | `/api/watcher/pause`, `/api/watcher/resume` | Pause or resume ingestion (409 when not enabled). |
| GET | `/api/intel/status` | Threat feeds: `id, name, source (network or demo), entries, fetched_at`. |
| POST | `/api/intel/refresh` | Body `{feeds?: [...]}`. Downloads the public feeds (the only network action; at most once an hour per feed). 422 for an unknown feed. Alerts and event details carry an `intel` field. |
| GET | `/api/incidents` | Filters `status, severity`; ordered by severity then last activity. |
| GET | `/api/incidents/{id}` | Incident with alerts (including `intel`), audit history, IPs, accounts and ATT&CK techniques. |
| PATCH | `/api/incidents/{id}` | Body `{status?, title?, note?}`; 422 for an illegal transition or empty title. |
| POST | `/api/incidents/{id}/notes` | Body `{text}`. |
| POST / DELETE | `/api/incidents/{id}/alerts`, `/api/incidents/{id}/alerts/{alert_id}` | Move an alert into an incident (body `{alert_id}`) or remove it (it will not be regrouped automatically). |
| POST | `/api/incidents/{id}/merge` | Body `{into}`; the source is closed. 422 for self-merge or a resolved target. |
| GET | `/api/collectors` | System log sources: `id, name, description, platform, enabled, access, state, events_read, last_activity, last_error`. `enabled: false` when system log collection is off (server mode). |
| PATCH | `/api/collectors/{id}` | Body `{enabled?, backfill_hours?}` (0 to 168). 404 unknown, 409 when collection is off. |
| POST | `/api/collectors/{id}/check` | Re-check access to one source. |
| POST | `/api/collectors/security/enable-access` | Asks Windows (through its own permission prompt) to add the current user to Event Log Readers. Returns `{requested, access}`. 409 off Windows. |
| GET / POST | `/api/setup`, `/api/setup/complete` | First-run setup state. |
| GET | `/api/scans/status` | `{enabled, engine, available, message}`. `enabled` is false outside the desktop app. |
| POST | `/api/scans` | Body `{paths: [...]}` (absolute, existing, local; at most 50). Starts a background Microsoft Defender scan and returns the scan (202). 422 bad path, 409 busy or disabled. |
| GET | `/api/scans`, `/api/scans/{id}` | Recent scans / one scan: `status` (running, completed, failed), `targets`, `results` (`path, status: clean|threat|error, message, threats[{threat, path, sha256, alert_id}]`), `done`, `total`, `threats`. |
| GET / PUT | `/api/mitigation/settings` | `{enabled, block_ip: off\|ask, quarantine_file: off\|ask\|auto, block_private, block_days (1-365), allowlist[]}`. 422 with a message for bad values (including `block_ip: auto`). `enabled` is false outside the desktop app. |
| GET | `/api/mitigation/alerts/{id}` | `{enabled, advice[], actions[], skipped[{kind,target,reason}]}`. Advice is always returned; actions only in the desktop app (proposals are created on first read). |
| GET | `/api/mitigation/history` | Recent actions. |
| POST | `/api/mitigation/{id}/approve`, `/dismiss`, `/undo` | Act on a proposal (approve runs in the background; poll the alert or history). 409 when the state does not allow it or off the desktop app, 404 unknown. |
| GET / POST / DELETE | `/api/suppressions`, `/api/suppressions/{id}` | Known false positives: `{rule_id?, source_ip?, username?, note}`; at least one field is required (422 otherwise), HZ-008 cannot be suppressed. A matching detection raises no alert and counts a hit. |
| POST | `/api/alerts/{id}/suppress` | Suppress alerts like this one (same rule, address, account) and resolve it. |
| GET / PUT | `/api/scans/downloads` | Scan new downloads: `{enabled, folder, default_folder, effective_folder, available, watching, queued, scanned}`; PUT `{enabled?, folder?}` (422 bad folder, 409 outside the desktop app). |
| GET | `/api/data/status` | `{backups_available, retention_days, events, oldest_event, database_bytes, restore_pending}`. |
| PUT | `/api/data/retention` | `{days}` 0 (keep everything) to 3650. Events that belong to an alert are never deleted. |
| POST | `/api/data/purge` | Delete old events now; returns `{removed, ...status}`. |
| POST / DELETE | `/api/data/backup`, `/api/data/restore` | Body `{path}`. Backup needs an absolute path ending in `.hzbackup` and never overwrites a file that is not a database; restore validates the file and stages it for the next start (DELETE cancels it). 422 with a message, 409 when unavailable. |
| GET / PUT | `/api/desktop/settings` | Desktop only: `{enabled, run_in_background, notify: critical\|high\|off, start_with_windows}`. |
| GET | `/api/health` | Liveness check. |

Alert transitions: OPEN to INVESTIGATING or RESOLVED; INVESTIGATING to RESOLVED or OPEN; RESOLVED to OPEN.
