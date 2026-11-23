# ML Anomaly Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add HZ-007 "Anomalous IP activity", an Isolation Forest rule over per-IP hourly windows, with training API/CLI, a dashboard card and demo data.

**Architecture:** A pure feature module, a deterministic synthetic baseline and a model bundle live in `backend/app/ml/`. `AnomalousIpActivity` is an ordinary `Rule` in `detection/` that loads the saved model and never raises. API and CLI only call the `ml` package.

**Tech Stack:** scikit-learn (IsolationForest, joblib), existing FastAPI/SQLAlchemy/React stack.

**Spec:** `docs/superpowers/specs/2026-11-23-ml-anomaly-detection-design.md`

## Global Constraints

- Window unit: (source_ip, hour). Events without `source_ip` are ignored.
- `FEATURE_NAMES = ["events", "failures", "successes", "distinct_users", "distinct_event_types", "failure_ratio", "off_hours"]`; off-hours means hour outside 08:00–18:00.
- IsolationForest `n_estimators=200`, `random_state=42`, `contamination=0.01`; minimum 50 training windows else `InsufficientData`.
- Rule id `HZ-007`, name `Anomalous IP activity`, default severity `medium` (`high` below the stricter cut-off), params `{"min_events": 3}`, key `HZ-007|<ip>|`, `window_minutes=60`.
- Model path from env `HORIZON_MODEL_PATH`, default `./horizon_model.joblib`. Missing/corrupt file means "not trained"; the rule then returns `[]`.
- Synthetic baseline: deterministic (`seed=42`), 21 days, about 30 internal `10.0.x.x` IPs, working-hours logins, occasional failures.
- Detection modules must not import `fastapi` or `sqlalchemy`. Use `/c/Users/.../.venv/Scripts/python.exe -m pytest` from `backend/`.

## Review Focus

- No model file, or a corrupt one: imports still succeed and no HZ-007 alert is created.
- Training on a nearly empty database: API returns 422 with a message suggesting `synthetic`, not a 500.
- Windows with fewer than `min_events` events are never alerted on.
- Existing databases (rules already seeded) gain HZ-007 without losing user-edited rule settings.
- Re-importing the same file creates no duplicate HZ-007 alert.

---

### Task 1: ML core (features, baseline, model)

**Files:**
- Create: `backend/app/ml/{__init__,features,baseline,model}.py`, `backend/tests/test_ml.py`
- Modify: `requirements.txt` (add `scikit-learn>=1.4`)

**Interfaces:**
- Produces `features`: `FEATURE_NAMES: list[str]`; `group_windows(events: list[Event]) -> dict[tuple[str, datetime], list[Event]]` (key = ip, hour start); `window_features(events: list[Event]) -> list[float]`.
- Produces `baseline.synthetic_baseline(seed: int = 42, days: int = 21) -> list[Event]`.
- Produces `model`: `class InsufficientData(ValueError)`; `@dataclass ModelBundle(model, means: list[float], stds: list[float], trained_at: str, n_windows: int, source: str, high_cutoff: float)`; `train(events, source: str, contamination: float = 0.01) -> ModelBundle`; `score(bundle, vector: list[float]) -> tuple[bool, float]` (is_outlier, score_samples value); `is_high(bundle, score: float) -> bool`; `explain(bundle, vector, top: int = 3) -> list[str]`; `save(bundle, path=None)`, `load(path=None) -> ModelBundle | None` (cached by mtime; `None` when missing/corrupt); `model_path() -> Path`.

- [ ] **Step 1: Write failing tests** in `test_ml.py`: `test_window_features_values` (3 failures + 1 success, 3 distinct users, 1 type pair → exact vector), `test_group_windows_ignores_events_without_ip`, `test_synthetic_baseline_is_deterministic` (two calls equal fingerprints, more than 50 windows), `test_train_raises_insufficient_data` (10 events), `test_spray_window_is_outlier_and_typical_is_not` (train on baseline; vector for 3 failures/3 distinct users/off-hours → outlier; typical 2 successes/0 failures → not), `test_explain_names_top_features` (spray vector explanation mentions "failures" and "distinct_users"), `test_load_returns_none_for_missing_and_corrupt` (tmp path, write garbage bytes), `test_save_load_roundtrip`.
- [ ] **Step 2: Run** `python -m pytest tests/test_ml.py -q` from `backend/` → FAIL (import error).
- [ ] **Step 3: Implement** the three modules and add the dependency (`uv pip install --python .venv/Scripts/python.exe -r requirements.txt`). `high_cutoff` = 0.1 percentile of baseline `score_samples`. `explain` returns strings like `"failures 3 (typical 0.2)"` for the features with the largest positive z-score (std floored at a small epsilon).
- [ ] **Step 4: Run** the tests → PASS.
- [ ] **Step 5: Commit** `feat: ML core for anomaly detection`.

### Task 2: HZ-007 rule, rule seeding, sample spray log

**Files:**
- Create: `backend/app/detection/anomaly.py`, `sample_logs/slow_spray.log`, `backend/tests/test_anomaly_rule.py`
- Modify: `backend/app/detection/rules.py` (register `AnomalousIpActivity` in `RULE_CLASSES`), `backend/app/database/repositories.py` (`RuleRepository.seed_defaults` inserts missing ids), `backend/app/seed.py` (add `("slow_spray.log", "linux_auth")` to `SAMPLES`), `backend/tests/test_statistics.py` and `test_ingestion.py` (update counts)

**Interfaces:**
- Consumes: Task 1 (`group_windows`, `window_features`, `score`, `is_high`, `explain`, `load`).
- Produces: `AnomalousIpActivity(Rule)` with `evaluate(new_events, history) -> list[Detection]`; `history.events_in_window(list(EventType), hour_start, hour_end, source_ip=ip)` supplies the full window. `slow_spray.log`: 10 failed-password lines for distinct valid-looking users from `198.51.100.77`, 3 per hour over 4 hours, never 5 within 5 minutes.

- [ ] **Step 1: Write failing tests**: `test_returns_empty_without_model` (model path to a missing tmp file), `test_returns_empty_with_corrupt_model`, `test_min_events_guard`, `test_spray_ip_flagged_with_explanation` (trained synthetic bundle saved to tmp path via monkeypatched `HORIZON_MODEL_PATH`; detections for `198.51.100.77`, key `HZ-007|198.51.100.77|`, description contains "failures"), `test_typical_activity_not_flagged`, `test_seed_defaults_adds_missing_rule_and_keeps_edits` (seed 6 rules, edit one threshold, call again with 7 defaults → 7 rows, edit kept), `test_import_creates_hz007_and_no_hz001_for_spray` (import `slow_spray.log` after training; one HZ-007 alert; zero HZ-001 for that IP), `test_reimport_creates_no_duplicate_alert`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** the rule (never raises: wrap model load/score in try/except returning `[]`), registration, `seed_defaults` change, sample file, and update existing test expectations (`sources == 6`; event-count assertions stay `> 40`).
- [ ] **Step 4: Run** the whole backend suite → PASS.
- [ ] **Step 5: Commit** `feat: HZ-007 anomalous IP activity rule`.

### Task 3: Training API, CLI and startup training

**Files:**
- Create: `backend/app/ml/service.py`, `backend/app/ml/train.py`, `backend/app/api/ml.py`, `backend/tests/test_ml_api.py`
- Modify: `backend/app/main.py` (include router), `backend/app/seed.py` (`main` trains the synthetic baseline first when no model exists), `backend/run_app.py` (set `HORIZON_MODEL_PATH` in the data folder; train before seeding if none)

**Interfaces:**
- Produces `service`: `status() -> dict` (`trained, trained_at, windows, source, features`); `train_from_database(session) -> ModelBundle` (all stored events with an IP; raises `InsufficientData`); `train_synthetic() -> ModelBundle`; both save the model. `ensure_model() -> bool` trains synthetic when none exists.
- Produces API: `GET /api/ml/status`; `POST /api/ml/train` body `{"source": "database" | "synthetic"}` returning status, 422 with detail on `InsufficientData` or an unknown source.
- CLI: `python -m app.ml.train [--source database|synthetic]`.

- [ ] **Step 1: Write failing tests**: `test_status_untrained`, `test_train_synthetic_then_status_trained`, `test_train_database_with_thin_data_422` (message contains "synthetic"), `test_train_unknown_source_422`, `test_end_to_end_spray_alert_via_api` (train synthetic, upload `slow_spray.log`, `GET /api/alerts?rule_id=HZ-007` total 1), `test_ensure_model_trains_only_when_missing`. Use a tmp `HORIZON_MODEL_PATH` per test.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** service, CLI, router, seed/launcher hooks. **Step 4: Run** the full suite → PASS.
- [ ] **Step 5: Commit** `feat: ML training API and startup training`.

### Task 4: Dashboard card, docs and executable rebuild

**Files:**
- Create: `frontend/src/components/ModelCard.jsx`
- Modify: `frontend/src/services/api.js` (`getModelStatus`, `trainModel(source)`), `frontend/src/pages/Analytics.jsx` (render the card), `README.md`, `docs/detection-rules.md` (HZ-007 row), `docs/architecture.md` (ML section, pickle warning), `scripts/build-exe.ps1` (add `--collect-submodules sklearn`)

**Interfaces:**
- Consumes: Task 3 endpoints. `ModelCard` shows trained state, time, window count, source, and two buttons ("Train on synthetic baseline", "Train on my data") with the server's error text on failure.

- [ ] **Step 1: Implement** `ModelCard` and API helpers; add the card above the rule table on Analytics.
- [ ] **Step 2: Verify build**: `npm run build` (with the pip-provided Node on PATH) passes.
- [ ] **Step 3: Verify in browser**: run the backend against a fresh DB and model path, seed, open Analytics: card shows trained, Alerts lists an HZ-007 alert for `198.51.100.77` whose description names its deviating features; "Train on my data" on a thin DB shows the 422 message; no console errors.
- [ ] **Step 4: Rebuild** `scripts\build-exe.ps1`, run the exe with a temp `LOCALAPPDATA`, confirm `/api/ml/status` is trained and an HZ-007 alert exists; report the new exe size. Run the full pytest suite one last time.
- [ ] **Step 5: Commit** `feat: anomaly model dashboard card and docs`.
