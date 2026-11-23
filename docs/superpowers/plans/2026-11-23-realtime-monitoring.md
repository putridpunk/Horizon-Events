# Real-time Monitoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A background watcher that ingests new lines from a watch folder (subfolder = source type), with status and pause/resume in the API and dashboard.

**Architecture:** A pure `FileTailer`, a `WatchService` thread that calls the existing `import_logs`, API routes reading `app.state`, and a dashboard card.

**Tech Stack:** Python threading, existing FastAPI/SQLAlchemy/React; no new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-23-realtime-monitoring-design.md`

## Global Constraints

- Source subfolders: `linux_auth, linux_syslog, windows, application, json` (the `SOURCE_TYPES` tuple). Poll interval 2 s; read cap 1 MiB per file per poll.
- Only complete lines (ending in `\n`) are ingested. Symlinks and nested folders are ignored.
- Env var `HORIZON_WATCH_DIR` enables the watcher; unset means `enabled: false`.
- Offsets are in memory; fingerprint dedupe protects against re-reads.
- Tests: `.venv/Scripts/python.exe -m pytest` from `backend/`.

## Review Focus

- Half-written last line is never parsed until its newline arrives.
- File truncated or replaced by a smaller one is re-read from the start (no stuck offset).
- File deleted mid-run does not crash the loop.
- Restart (new service, same files) adds no duplicate events or alerts.
- Binary garbage in a watched file is skipped, not fatal.

---

### Task 1: FileTailer

**Files:**
- Create: `backend/app/watcher/__init__.py`, `backend/app/watcher/tailer.py`, `backend/tests/test_tailer.py`

**Interfaces:**
- Produces: `FileTailer()` with `read_new(path: Path, max_bytes: int = 1_048_576) -> bytes` and attribute `offset: int`.

- [ ] **Step 1: Write failing tests**: `test_returns_only_appended_lines`, `test_partial_line_held_until_newline`, `test_truncation_resets_offset` (file rewritten shorter → returns new content), `test_missing_file_returns_empty`, `test_cap_limits_bytes_and_continues_next_call` (cap 10 bytes: never splits mid-line; a line longer than the cap is read whole), `test_empty_file_returns_empty`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** (open in binary, seek to offset, read up to the cap, cut at the last `\n`, advance offset by the consumed length; if a single line exceeds the cap read until its newline). **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: file tailer for the watch folder`.

### Task 2: WatchService

**Files:**
- Create: `backend/app/watcher/service.py`, `backend/tests/test_watcher.py`

**Interfaces:**
- Consumes: `FileTailer`, `import_logs`, `SOURCE_TYPES`.
- Produces: `WatchService(watch_dir: Path, session_factory: Callable[[], Session], interval: float = 2.0)` with `scan_once() -> int` (events imported this pass), `start()`, `stop()`, `pause()`, `resume()`, `status() -> dict` (`enabled, running, paused, directory, interval, files: [{path, source_type, lines, imported, alerts, last_activity, last_error}], total_imported`). File paths in status are relative with forward slashes.

- [ ] **Step 1: Write failing tests** (tmp watch dir, `session_factory` over the in-memory engine from conftest): `test_ingests_appended_lines_and_raises_alert` (12 failed-password lines in two appends; HZ-001 alert exists after the second scan), `test_unknown_subfolder_and_nested_ignored`, `test_symlink_ignored` (skip if symlink creation fails), `test_pause_stops_and_resume_continues`, `test_failing_file_does_not_stop_others` (monkeypatch `import_logs` to raise for one filename), `test_restart_does_not_duplicate` (new service on same files, event and alert counts unchanged), `test_deleted_file_does_not_crash`, `test_garbage_file_counted_as_skipped`, `test_thread_smoke` (start with interval 0.1, append, poll up to 5 s for the event, stop joins).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** (create subfolders on first scan; one session per file per scan, closed in `finally`; lock around shared stats; `stop()` sets an event and joins). **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: watch folder service`.

### Task 3: API, lifespan, launcher and Docker wiring

**Files:**
- Create: `backend/app/api/watcher.py`, `backend/tests/test_watcher_api.py`
- Modify: `backend/app/main.py` (lifespan starts/stops the service when `HORIZON_WATCH_DIR` is set and stores it in `app.state.watcher`; include router), `backend/run_app.py` (default `HORIZON_WATCH_DIR` in the data folder, print it), `docker-compose.yml` (mount `./watch:/watch`, env `HORIZON_WATCH_DIR=/watch`), `backend/Dockerfile` (no change expected), `.gitignore` (`watch/*` except a `.gitkeep`)

**Interfaces:**
- `GET /api/watcher/status` → service status or `{"enabled": false}`; `POST /api/watcher/pause` and `/resume` → status (409 when not enabled).

- [ ] **Step 1: Write failing tests**: `test_status_disabled`, `test_status_enabled_lists_files` (service attached to `app.state.watcher`, one `scan_once`), `test_pause_resume`, `test_pause_when_disabled_409`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** full suite → PASS.
- [ ] **Step 5: Commit** `feat: watcher API and wiring`.

### Task 4: Dashboard card, docs, executable check

**Files:**
- Create: `frontend/src/components/LiveCard.jsx`, `watch/.gitkeep`
- Modify: `frontend/src/services/api.js` (`getWatcherStatus`, `pauseWatcher`, `resumeWatcher`), `frontend/src/pages/Overview.jsx`, `README.md`, `docs/architecture.md`, `docs/api.md`

**Interfaces:**
- `LiveCard` polls status every 3 s; shows state (Live, Paused, Not configured), folder, files table, Pause/Resume buttons.

- [ ] **Step 1: Implement** card, wiring, docs (watch folder layout, supported source types, limits).
- [ ] **Step 2: Verify build**: `npm run build` passes.
- [ ] **Step 3: Rebuild and run the exe**; append lines to `%LOCALAPPDATA%\HorizonEvents\watch\linux_auth\live.log` with PowerShell (a brute-force burst), confirm `/api/statistics/overview` grows and a new HZ-001 alert appears within a few seconds, and the card shows the file in the browser pane; pause and confirm nothing new is ingested; run the full suite.
- [ ] **Step 4: Commit** `feat: live monitoring card and docs`.
