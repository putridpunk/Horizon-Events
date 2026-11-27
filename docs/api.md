# REST API

Interactive documentation is served at `/docs` when the backend runs.

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/imports` | Multipart upload: `file`, `source_type` (`linux_auth`, `linux_syslog`, `windows`, `application`, `json`). 413 above 10 MB, 422 for an unknown type. |
| GET | `/api/events` | Filters `query` (the search language, 422 with an explanation when it cannot be understood), `q` (plain text, older), `source, event_type, severity, start, end`; pagination `limit, offset`. Returns `{items, total}`. |
| GET | `/api/events/export` | Same filters as the list plus `format` (`csv` or `json`) and `limit` (up to 50,000, default 10,000); newest first; `X-Total-Matches` header. |
| GET | `/api/events/{id}` | One event including the raw log line. |
| GET / POST / DELETE | `/api/searches`, `/api/searches/{id}` | Saved searches `{name, query}`; the query is checked when saved (422 says why). Up to 50, names are unique. |
| GET | `/api/stream` | Server-sent events. Each `change` event is `{"changed": ["alerts", "events", ...]}`; at most 20 open connections (503 beyond). |
| GET | `/api/syslog/status` | `{enabled}`, and when on: bind, port, received, imported, alerts, queued, dropped, last_message, last_error. |
| POST | `/api/intel/import` | Multipart `name`, `file` (STIX 2.1, MISP or text; 10 MB). A list with the same name is replaced. 422 says why. |
| DELETE | `/api/intel/feeds/{id}` | Remove an imported list (ids start with `user:`; the built-in feeds cannot be removed). |
| GET | `/api/alerts` | Filters `severity, status, rule_id, assignee` (a name, or `unassigned`), `tag`; ordered by severity, then recency. Each alert also carries `assignee, tags, age_minutes, sla_minutes, sla_due_at, sla_breached`. |
| GET | `/api/alerts/tags` | `{tags, assignees}` in use, for filter menus. |
| PATCH | `/api/alerts/{id}/triage` | Body `{assignee?, tags?}`; a field left out is unchanged, `assignee: null` unassigns. Up to 10 tags of 30 characters. Each change is written to the alert history. 422 for invalid values. |
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
| GET / POST | `/api/notifications` | Notification channels. POST `{name, kind: webhook\|slack\|discord\|email, config, min_severity, enabled}`. Webhook `{url, secret?}`, Slack and Discord `{url}` (https only), email `{host, port?, security: starttls\|ssl\|none, username?, password?, from_addr, to_addrs}`. Secrets are never returned: the API shows `url_host`, `has_url`, `has_secret`, `has_password`. 422 for invalid settings. |
| PATCH / DELETE | `/api/notifications/{id}` | Change a channel (a secret left out keeps its old value), or remove it (409 while a scheduled report emails through it). |
| POST | `/api/notifications/{id}/test` | Send a test message; returns `{ok, error, channel}`. |
| GET / POST | `/api/report-schedules` | Scheduled reports `{name, frequency: daily\|weekly, format: html\|csv\|json, email_channel_id?, enabled}`. Runs at 07:00 UTC (weekly: Monday). |
| PATCH / DELETE | `/api/report-schedules/{id}` | Change or remove a schedule. |
| POST | `/api/report-schedules/{id}/run` | Make the report now. |
| GET | `/api/report-schedules/{id}/latest` | Download the most recent file (404 if none). |
| POST | `/api/rules/custom` | Create a rule of your own `{name, description?, severity, params, enabled}`; `params` is `{when, threshold, window_minutes, group_by}` (see detection-rules.md). 422 says what is wrong. Ids are `CR-001`... |
| PUT / DELETE | `/api/rules/custom/{id}` | Replace or remove one of your rules (404 for built-in rules). |
| POST | `/api/rules/sigma` | `{text, save?: true, enabled?: true}`: convert a Sigma rule. With `save: false` it only returns the result. 422 explains anything unsupported. |
| POST | `/api/rules/replay` | `{rule_id?, severity?, params?, name?, days}`: what a stored rule (with the given overrides) or a draft custom rule would have flagged over the last `days` (1 to 90). Saves nothing. |
| GET / PUT | `/api/geoip` | The location database: `{configured, path, database, error}`; PUT `{path}` (an absolute `.mmdb` path, or `null` to stop). 422 says why a file cannot be used. |
| GET | `/api/auth/status` | `{enabled, setup_required, user}`. Always open. |
| POST | `/api/auth/setup`, `/api/auth/login`, `/api/auth/logout`, `/api/auth/password` | First administrator (`{token, username, password}`), sign in, sign out, change your own password (`{current_password, new_password}`). Only when `HORIZON_AUTH=1`. 401 wrong credentials, 429 locked or too many attempts. |
| GET / POST | `/api/users` | Administrators only: list, and create `{username, password, role}` (viewer, analyst, admin). |
| PATCH / DELETE | `/api/users/{id}` | Administrators only: `{role?, disabled?, password?, unlock?}`; 409 when it would leave no active administrator or acts on yourself. |
| GET | `/api/audit` | Administrators only: recent sign-ins and changes. |
| GET | `/api/update` | `{current, latest, update_available, url, notes, checked_at, auto_check, error}`. |
| POST | `/api/update/check` | Ask GitHub for the latest release now. |
| PUT | `/api/update/settings` | `{auto_check}`: check once a day (off by default). |
| GET | `/api/health` | Liveness check. |

Alert transitions: OPEN to INVESTIGATING or RESOLVED; INVESTIGATING to RESOLVED or OPEN; RESOLVED to OPEN.
