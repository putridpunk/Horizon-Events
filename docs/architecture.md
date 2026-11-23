# Architecture

Horizon Events is a modular monolith. Each layer has one responsibility and depends only on layers below it.

```
api  ->  services  ->  collectors / processors / detection / alerts  ->  domain
                  \->  database (models + repositories)
```

| Layer | Responsibility | Framework imports |
| --- | --- | --- |
| `domain.py` | `Event`, `Detection`, enums | none |
| `collectors/`, `processors/` | bytes -> parsed dicts -> `Event` | none |
| `detection/` | `Rule` classes and `DetectionEngine` | none |
| `alerts/` | alert creation, de-duplication, status workflow | repositories only |
| `database/` | SQLAlchemy models, repositories | SQLAlchemy |
| `services/` | orchestration (`import_logs`) and statistics | SQLAlchemy |
| `api/` | HTTP routing and validation | FastAPI |

## Import flow

1. `collect(source_type, bytes)` parses and normalises, counting imported and skipped lines.
2. `EventRepository.add_many` stores events, ignoring ones already stored (SHA-256 fingerprint of source, timestamp and raw line).
3. `DetectionEngine` runs the enabled rules over the **newly stored** events. Rules look back through `EventHistory` for windowed counts.
4. `AlertManager` creates alerts or merges detections into an existing open alert with the same key within the de-duplication window (30 minutes of event time).

## Extending

- **New log source:** add a parser, a collector iterator and an entry in `collectors/base.py`.
- **New rule:** subclass `Rule`, register it in `RULE_CLASSES`. Defaults are seeded into the `detection_rules` table automatically.
- **ML detector:** implement `Rule.evaluate(new_events, history)` and register it in `detection/registry.py`; nothing else changes. HZ-007 does exactly this (`detection/anomaly.py`, with feature extraction, the synthetic baseline and the model in `ml/`).
- **PostgreSQL:** set `DATABASE_URL`; models use portable column types only.

## Live monitoring

`watcher/tailer.py` reads only the complete new lines of a growing file (a pure helper). `watcher/service.py` polls the watch folder from a background thread and feeds each batch to `import_logs`, so detection and alerting are identical to a manual import. Per-file errors are recorded and retried; the loop never stops. Offsets are kept in memory, and the event fingerprint makes re-reading after a restart harmless. The service starts only when `HORIZON_WATCH_DIR` is set.

## Threat intelligence

`intel/feeds.py` holds the feed definitions, parsers and the local `IpMatcher` (pure Python). `intel/service.py` stores feed entries in `intel_feeds` / `intel_entries`, refreshes them only on request (https, size-capped, one hour minimum between refreshes, previous data kept on failure) and enriches IPs on read, so alerts always reflect the current feed data. Feed URLs are constants; users cannot supply URLs.

## Incidents

`incidents/manager.py` groups alerts into incidents without any SQL (`database/incident_repository.py` holds the queries). After every import, each new or updated alert is correlated: it joins the lowest-numbered open (not RESOLVED) incident that contains an alert with the same source IP or the same account and whose last activity is within 24 hours of the alert's event time; otherwise it opens a new incident. Alerts with neither an IP nor an account are not grouped automatically. Incident severity is the highest severity among its alerts. Analysts can move, remove and merge alerts; a removed alert is remembered in `incident_exclusions` so it is not regrouped. Incident status is independent of alert status. Every change is written to `incident_history`. At startup, alerts that predate incidents are grouped by `backfill()` (idempotent).

## System log collection

`system/` holds a `Collector` interface and a `CollectorManager` thread (5 s interval, per-collector error isolation) that is started only when `HORIZON_SYSTEM_LOGS=1` (the desktop app sets it). `windows_eventlog.py` runs the built-in `wevtutil` by full path through an injectable runner, with an XPath filter for a fixed list of event IDs and a record-ID bookmark stored in the database after each successful import; the events then follow the normal `import_logs` path. Access states come from `wevtutil` exit codes, not message text, so they do not depend on the Windows language. `access.py` builds the one-time Event Log Readers request from the current user's SID and asks Windows to run it elevated; the code never runs that command itself. `linux_logs.py` follows fixed log files with the existing tailer. Setup state lives in the `app_settings` table.

## Model file security

The trained model is stored with `joblib`, which uses pickle. Horizon Events writes it to its own data folder (`HORIZON_MODEL_PATH`, default `./horizon_model.joblib`; `/data` in Docker; `%LOCALAPPDATA%\HorizonEvents` for the executable). Never point `HORIZON_MODEL_PATH` at a file you did not create: loading an untrusted pickle can run arbitrary code. A missing or unreadable file is treated as "not trained".
