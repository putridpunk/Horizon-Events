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
| GET | `/api/health` | Liveness check. |

Alert transitions: OPEN to INVESTIGATING or RESOLVED; INVESTIGATING to RESOLVED or OPEN; RESOLVED to OPEN.
