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

## Model file security

The trained model is stored with `joblib`, which uses pickle. Horizon Events writes it to its own data folder (`HORIZON_MODEL_PATH`, default `./horizon_model.joblib`; `/data` in Docker; `%LOCALAPPDATA%\HorizonEvents` for the executable). Never point `HORIZON_MODEL_PATH` at a file you did not create: loading an untrusted pickle can run arbitrary code. A missing or unreadable file is treated as "not trained".
