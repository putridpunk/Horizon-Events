# ML Anomaly Detection (Milestone 5, part 1) — Design

Date: 2026-11-23. Builds on `2026-11-23-horizon-events-design.md`.

## Intent

Flag behaviour the six fixed-threshold rules miss, using an Isolation Forest, and show it through the existing alerts, API and dashboard. It is a portfolio feature: it must be explainable ("why was this flagged?"), demonstrable from a clean start, and tested without flaky randomness.

## Goals

- A seventh rule, **HZ-007 "Anomalous IP activity"**, implemented as a normal `Rule` so the engine, alert manager and dashboard need no structural change.
- Model unit: **one source IP in one hour** (events with no source IP are ignored).
- Features per window: event count, failure count, success count, distinct usernames, distinct event types, failure ratio, off-hours flag (hour outside 08:00–18:00).
- Alerts explain themselves: the description names the 2–3 features that deviate most from the training baseline (z-score), e.g. "authentication failures 3 (typical 0.2), distinct users 3 (typical 0.1)".
- Training via API (`POST /api/ml/train`, source `database` or `synthetic`), CLI (`python -m app.ml.train`), and a small status/train card on the Analytics page.
- Demo works out of the box: a deterministic synthetic baseline (21 days, ~30 internal IPs, mostly working-hours logins, occasional failures) trains the model; `seed` and the `.exe`/Docker startup train it first if none exists. A new sample log, `slow_spray.log`, holds a slow password spray (about 10 failures across 4 hours, 3 per hour, 3+ distinct users from `198.51.100.77`) that no existing rule catches but HZ-007 flags.

## Non-goals

Per-user or per-event models, online/incremental learning, model versioning, hyperparameter UI, GPU/large-scale performance.

## Approaches considered

- **Per-event scoring** — noisy, unexplainable. Rejected.
- **Per-user windows** — too few rows in the demo data. Rejected.
- **Per-IP hourly windows (chosen, confirmed by the user)** — catches low-and-slow spraying, gives a natural alert subject (the IP), explainable features.

## Design

- `backend/app/ml/features.py`: `FEATURE_NAMES`, `window_features(events) -> list[float]`, `group_windows(events) -> dict[(ip, hour_start), list[Event]]`. Pure Python.
- `backend/app/ml/baseline.py`: `synthetic_baseline(seed=42, days=21) -> list[Event]`, deterministic.
- `backend/app/ml/model.py`: `ModelBundle` (IsolationForest, per-feature mean/std, trained_at, n_windows, source). `train(events, source, contamination=0.01) -> ModelBundle` uses `random_state=42`, `n_estimators=200`; needs at least 50 windows, otherwise raises `InsufficientData`. `explain(bundle, features) -> list[str]`. Save/load with joblib at `HORIZON_MODEL_PATH` (default `./horizon_model.joblib`; the executable sets it inside its data folder). Loading is cached by file mtime; a missing or corrupt file means "not trained".
- `backend/app/detection/anomaly.py`: `AnomalousIpActivity(Rule)`, id `HZ-007`, default severity `medium`, params `{"min_events": 3}`. For each (ip, hour) window touched by new events it reloads the whole window from history, skips windows under `min_events`, scores with the model, and emits a detection when the model predicts an outlier. Severity is `high` when the score is below a second, stricter cut-off (training-time 0.1 percentile of baseline scores), else `medium`. Detection key `HZ-007|<ip>|`, `window_minutes=60`. With no usable model it returns `[]` and never raises.
- `RuleRepository.seed_defaults` is changed to insert any default rule missing from the table, so existing databases pick up HZ-007.
- API: `GET /api/ml/status` → `{trained, trained_at, windows, source, features}`; `POST /api/ml/train` with `{source}` → status, or 422 with a clear message when the database has too little data (suggesting `synthetic`).
- Frontend: an "Anomaly model" card on Analytics (status, Train on synthetic baseline, Train on my data).
- Dependencies: `scikit-learn` added to `requirements.txt`. The `.exe` grows (accepted); Docker image grows too.
- Security: the model file is loaded with joblib (pickle). It is created by the app in its own data folder; docs say never to point `HORIZON_MODEL_PATH` at an untrusted file.

## Testing

Deterministic baseline and fixed `random_state`. Unit: features, baseline determinism, `InsufficientData`, train + explain, spray window flagged and typical window not, rule returns `[]` without a model or with a corrupt file, `min_events` guard, `seed_defaults` adds a missing rule. Integration: train synthetic, import `slow_spray.log`, HZ-007 alert for `198.51.100.77` (and no HZ-001 for it); API status/train round-trip and 422 on thin data. Existing tests are updated where adding the sample file changes counts (sources 5 to 6).

## Left to the builder

Exact z-score wording, how the explanation is trimmed, baseline traffic shapes beyond the stated ones, and the Analytics card layout.
