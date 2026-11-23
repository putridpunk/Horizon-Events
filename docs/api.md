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
| GET | `/api/health` | Liveness check. |

Alert transitions: OPEN to INVESTIGATING or RESOLVED; INVESTIGATING to RESOLVED or OPEN; RESOLVED to OPEN.
