# System Log Collection Implementation Plan (project 2 of 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The desktop app reads this machine's own event logs continuously (Windows Event Log; Linux log files best effort), with a first-run setup, a Data sources page and a one-time Security log access flow.

**Architecture:** A `Collector` interface and a `CollectorManager` thread under `app/system/`. The Windows collector shells out to the built-in `wevtutil` through an injectable runner, bookmarks by record ID in the database, and feeds `import_logs`, so detection, alerts and incidents work unchanged.

**Tech Stack:** Python stdlib (`subprocess`, `ctypes`), `defusedxml`, existing FastAPI/SQLAlchemy/React; no new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-23-desktop-and-system-logs-design.md`

## Global Constraints

- Collected events: Security `4625, 4740, 4720, 4728, 4732, 4756` and `4624` only where `LogonType` is `2, 7, 10 or 11`; System `7031, 7034`; Application `1000`. Nothing else is read.
- Poll interval 5 s; batch `/c:200`, repeat while a batch is full. Collection starts from "now"; optional backfill of N hours (default offer 24).
- `wevtutil` exit codes decide state, never message text: `0` readable, `5` access denied, `15007` channel missing, `15001` bad query, anything else error.
- Security Event Log Readers group is addressed by SID `S-1-5-32-573` (works in any language). The elevation command is **never executed by tests or by the agent**; it is built, asserted as a string, and run only by the user's click.
- Collectors run only when env `HORIZON_SYSTEM_LOGS=1` (set by the desktop launcher). Server and Docker mode stay off by default.
- All reading is local; nothing is sent anywhere. Real-machine tests read only the System channel and assert structure, never content, and are skipped off Windows.
- Run tests with `.venv/Scripts/python.exe -m pytest` from `backend/`.

## Review Focus

- Security channel denied: no crash, state `needs_permission`, the other channels keep collecting.
- Restart does not re-read old events and does not skip new ones (bookmark persisted only after a successful import).
- First start does not flood the dashboard with history (starts from the newest record unless backfill was chosen).
- Event text containing `<`, `&`, quotes or non-ASCII is parsed and stored intact.
- A hung or failing `wevtutil` (timeout, non-zero exit, empty output) is recorded as `last_error` and retried, never fatal.
- Disabling a collector stops polling it immediately; re-enabling resumes from the bookmark.
- Sample-file imports and all existing tests behave exactly as before.

---

### Task 1: Parser support for real Windows events

**Files:**
- Modify: `backend/app/collectors/windows.py`, `backend/app/processors/parser.py`
- Create: `backend/tests/fixtures/eventlog/{security.xml,system.xml,application.xml}` (synthetic but real-shaped), `backend/tests/test_eventlog_parsing.py`

**Interfaces:**
- `_xml_events` also copies `EventRecordID`, `Channel` and `Provider` name; unnamed `<Data>` elements become `Data0`, `Data1`, … . `parse_windows_record` keeps `EventRecordID`/`Channel` in `raw`; for `4728, 4732, 4756` the username is `SubjectUserName`; `1000` maps to `service_failure` with `service = Data0`. Existing behaviour for the sample files is unchanged.

- [ ] **Step 1: Write failing tests**: `test_security_4625_fields` (user, IP, failure type), `test_4624_interactive_parsed`, `test_4740_lockout_user_is_the_locked_account`, `test_privileged_group_change_uses_the_subject_user`, `test_system_7031_service_name`, `test_application_1000_uses_first_unnamed_data_as_service`, `test_record_id_makes_identical_looking_events_distinct`, `test_special_characters_roundtrip`, `test_sample_windows_events_still_parse` (existing sample file results unchanged).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** the full suite → PASS.
- [ ] **Step 5: Commit** `feat: parse real-shaped Windows Event Log records`.

### Task 2: Collector framework, settings persistence, manager

**Files:**
- Create: `backend/app/database/collector_models.py`, `backend/app/system/{__init__,base,manager}.py`, `backend/tests/test_collector_manager.py`
- Modify: `backend/app/database/connection.py` (register the new models)

**Interfaces:**
- Tables: `CollectorSettingRow(id pk, enabled, backfill_hours, last_record_id, events_read, last_activity, last_error)`, `AppSettingRow(key pk, value)`. Helper functions `get_setting(session, key, default)` / `set_setting`.
- `Collector` (ABC): attributes `id, name, description, platform`; `access() -> str` (one of `ready, needs_permission, waiting_signout, unavailable`); `poll(session) -> int` (events imported). `CollectorManager(collectors, session_factory, interval=5.0)`: `start() / stop() / pause() / resume()`, `poll_once() -> int` (skips disabled and not-ready collectors, isolates exceptions into `last_error`), `status() -> list[dict]` (`id, name, description, platform, enabled, state, events_read, last_activity, last_error`), `set_enabled(id, enabled, backfill_hours=None)`, `check(id) -> dict`. `state` is `off` when disabled, otherwise the collector's access value, or `collecting` when ready and polling.

- [ ] **Step 1: Write failing tests** (fake collectors): `test_poll_once_runs_enabled_ready_collectors_only`, `test_exception_is_recorded_and_others_continue`, `test_disable_stops_polling_enable_resumes`, `test_status_states`, `test_settings_survive_a_new_manager`, `test_thread_start_stop`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: collector framework`.

### Task 3: Windows Event Log collector

**Files:**
- Create: `backend/app/system/windows_eventlog.py`, `backend/tests/test_windows_eventlog.py`

**Interfaces:**
- `CHANNELS: dict[str, ChannelSpec]` as in Global Constraints. `build_query(spec, after_id: int | None, backfill_ms: int | None = None) -> str` (XPath: `*[System[(EventID=… or …) and (EventRecordID>N)]]`, plus `or *[System[(EventID=4624) and (EventRecordID>N)] and EventData[(Data[@Name='LogonType']='2') or …]]` for Security; time window `TimeCreated[timediff(@SystemTime) <= ms]` for backfill). `run_wevtutil(args: list[str], timeout: float = 20) -> tuple[int, str]`. `probe(channel, runner) -> str` (state from exit code). `WindowsEventLogCollector(channel, runner=run_wevtutil)`: `access()`, `poll(session)` (query after the bookmark, wrap the output in `<Events>…</Events>`, call `import_logs(session, "windows", f"EventLog:{channel}", xml)`, advance the bookmark to the highest record ID only after the import succeeds). First poll with no bookmark: read the newest record ID (`/rd:true /c:1`) and start there, or run the backfill query.

- [ ] **Step 1: Write failing tests** (fake runner returning fixtures): `test_query_for_each_channel` (exact strings), `test_query_accepted_by_real_wevtutil` (Windows only: run the Security-shaped query against the System channel, expect exit 0 and no content assertions), `test_first_poll_starts_from_now_without_importing_history`, `test_backfill_imports_the_window_once`, `test_poll_imports_and_advances_the_bookmark`, `test_failed_import_keeps_the_bookmark`, `test_bookmark_survives_restart_and_nothing_is_reimported`, `test_batches_repeat_until_empty`, `test_exit_codes_map_to_states` (0, 5, 15007, 15001, other), `test_timeout_and_empty_output_are_errors_not_crashes`, `test_alert_created_for_failed_logon_burst` (end to end with fixtures: 8 events of 4625 → HZ-001 alert), `test_real_system_channel_is_readable_structure_only` (Windows only, opt-in via `HORIZON_REAL_EVENTLOG_TESTS=1`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: Windows Event Log collector`.

### Task 4: Security log access flow

**Files:**
- Create: `backend/app/system/access.py`, `backend/tests/test_access.py`

**Interfaces:**
- `SECURITY_READERS_SID = "S-1-5-32-573"`; `current_user() -> str` (`DOMAIN\user`); `enable_command(user: str) -> list[str]` (PowerShell: `Add-LocalGroupMember -SID S-1-5-32-573 -Member '<user>'`, user quoted safely and validated against a strict pattern); `is_member(runner, user) -> bool` (`Get-LocalGroupMember -SID …`); `token_has_group(runner) -> bool` (`whoami /groups /fo csv` contains the SID); `security_state(probe_state, member, in_token) -> str` (`ready` when readable; `waiting_signout` when a member but not yet in the token; else `needs_permission`); `request_elevation(args) -> bool` (`ShellExecuteW(None, "runas", "powershell.exe", …, SW_HIDE)`, return whether Windows accepted the request).

- [ ] **Step 1: Write failing tests**: `test_enable_command_exact_string_and_quoting` (names with spaces, apostrophes and a backslash are quoted or rejected; injection attempts such as `x'; calc; '` rejected), `test_state_matrix` (all combinations), `test_is_member_and_token_parsing` (fake runner output, locale-independent because it matches SIDs), `test_request_elevation_uses_runas_and_is_not_executed_in_tests` (inject a fake shell function), `test_non_windows_returns_unavailable`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: Security log access flow`.

### Task 5: Linux collector

**Files:**
- Create: `backend/app/system/linux_logs.py`, `backend/tests/test_linux_logs.py`

**Interfaces:**
- `LinuxLogCollector(id, name, source_type, paths: list[Path])`: reads the first existing path with `FileTailer`, imports through `import_logs(session, source_type, filename, data)`; `access()` is `unavailable` when no path exists, `needs_permission` when it exists but cannot be read, else `ready`. Defaults: `linux_auth` over `/var/log/auth.log`, `/var/log/secure`; `linux_syslog` over `/var/log/syslog`, `/var/log/messages`. Starts at the end of the file on first run (no history flood).

- [ ] **Step 1: Write failing tests** (temp files): `test_ready_unavailable_and_permission_states`, `test_first_poll_starts_at_the_end`, `test_new_lines_are_imported_and_alert`, `test_prefers_the_first_existing_path`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: Linux log collectors`.

### Task 6: API, setup state and wiring

**Files:**
- Create: `backend/app/api/collectors.py`, `backend/tests/test_collectors_api.py`
- Modify: `backend/app/main.py` (build collectors by platform, start the manager when `HORIZON_SYSTEM_LOGS=1`, keep it on `app.state.collectors`), `backend/run_app.py` (set `HORIZON_SYSTEM_LOGS=1`)

**Interfaces:**
- `GET /api/collectors` → `{enabled: bool, platform, items: [status…]}` (`enabled: false` when the manager is off). `PATCH /api/collectors/{id}` body `{enabled?, backfill_hours?}`. `POST /api/collectors/{id}/check` → status. `POST /api/collectors/security/enable-access` → `{requested: bool, state}`; 409 on non-Windows or when the manager is off. `GET /api/setup` → `{completed, system_logs_enabled, platform}`; `POST /api/setup/complete`. Unknown collector → 404; `backfill_hours` outside 0 to 168 → 422.

- [ ] **Step 1: Write failing tests** (manager with fake collectors on `app.state`): list, patch, check, 404, 422, setup flow, enable-access calls the injected elevation function exactly once and never runs a real one, state-changing calls obey the Origin guard, off-state responses.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** the full suite → PASS.
- [ ] **Step 5: Commit** `feat: collectors API and setup state`.

### Task 7: Setup screen, Data sources page, docs, verification

**Files:**
- Create: `frontend/src/pages/Setup.jsx`, `frontend/src/pages/Sources.jsx`, `frontend/src/components/SourceRow.jsx`, tests for each
- Modify: `frontend/src/services/api.js`, `frontend/src/App.jsx` (redirect to `/setup` until completed when system logs are enabled), `frontend/src/components/Layout.jsx` (Data sources link), `frontend/src/pages/Overview.jsx` (move the watch-folder card into Data sources, Advanced), `README.md`, `docs/architecture.md`, `docs/security.md`, `docs/api.md`

**Interfaces:**
- Setup shows: what is read and that it stays on this machine; one row per collector with its state, an enable switch and, for Security, **Enable access** with a confirmation dialog that names exactly what will happen (add you to *Event Log Readers*, one Windows permission prompt, then sign out and in once); a **Backfill the last 24 hours** option; **Start collecting**. Data sources lists the same rows live (3 s refresh) plus last event time, events read, last error and **Check access**; Advanced holds the watch folder and manual import.

- [ ] **Step 1: Write failing tests**: states render (collecting, needs permission, waiting for sign-out, unavailable, off); the confirmation names the group change; Enable access calls the API only after confirming; Start collecting saves choices then completes setup; redirect gating; errors surface the server message.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** (existing styling; the UI plan restyles everything later). **Step 4: Run** frontend tests and build → PASS.
- [ ] **Step 5: Verify on this machine** with the rebuilt app (or `run_app.py`): System and Application show **Collecting**, Security shows **Needs permission**; a backfill of 24 hours imports real System events (report only counts and states, never event content; no screenshots of real data); the elevation command is not run. Tell the user how to click **Enable access** and what to expect (Windows prompt, then sign out and in).
- [ ] **Step 6: Commit** `feat: setup screen and Data sources page`.
