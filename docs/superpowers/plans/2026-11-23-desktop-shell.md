# Desktop Shell Implementation Plan (project 1 of 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The Windows `.exe` opens its own native window (no browser, no console), protected by a per-launch session secret, as a single instance.

**Architecture:** `app/desktop.py` holds the testable pieces (free port, secret, session guard middleware, single-instance lock). `run_app.py` wires them: uvicorn on a thread, pywebview window on the main thread. Server mode (Docker, `uvicorn app.main:app`) is unchanged.

**Tech Stack:** pywebview (WebView2 on Windows), PyInstaller (windowed), Pillow for the icon script (dev only).

**Spec:** `docs/superpowers/specs/2026-11-23-desktop-and-system-logs-design.md` (section "Desktop shell")

## Global Constraints

- Window title `Horizon Events`, default size 1360x860, minimum 1100x700. Server binds `127.0.0.1` on a random free port.
- Session secret: `secrets.token_urlsafe(32)` per launch, passed through env `HORIZON_SESSION_SECRET`. Cookie `hz_session`: `HttpOnly`, `SameSite=Strict`, `Path=/`. Compare with `hmac.compare_digest`. When the variable is unset the guard does nothing.
- No browser fallback: if the native window cannot start, show a message box with the WebView2 download link `https://developer.microsoft.com/microsoft-edge/webview2/` and exit with code 1.
- WebView2 storage (localStorage, used for the theme) must persist: pass `storage_path` in the data folder.
- Data folder stays `%LOCALAPPDATA%\HorizonEvents`; logs go to `desktop.log` there. Run tests with `.venv/Scripts/python.exe -m pytest` from `backend/`.

## Review Focus

- A request with a wrong or missing cookie never reaches the API (401), including static files and the SPA index.
- The bootstrap query parameter is stripped by the redirect (the secret must not stay in the address, history or logs).
- A second launch exits cleanly and does not disturb the first; a crashed first instance leaves no stale lock.
- Closing the window stops the server and the process exits (no orphan process holding the database).
- Server mode and every existing test are unaffected.

---

### Task 1: Desktop helpers and session guard

**Files:**
- Create: `backend/app/desktop.py`, `backend/tests/test_desktop.py`
- Modify: `backend/app/main.py` (add `SessionGuard`), `backend/tests/conftest.py` (clear `HORIZON_SESSION_SECRET` for tests)

**Interfaces:**
- Produces: `pick_free_port() -> int`; `make_secret() -> str`; `class SessionGuard` (ASGI middleware; reads `HORIZON_SESSION_SECRET` per request); `class SingleInstance(path: Path)` with `acquire() -> bool` and `release()` (file lock: `msvcrt.locking` on Windows, `fcntl.flock` elsewhere; released automatically if the process dies); `wait_until_ready(url: str, timeout: float = 15) -> bool`.
- Guard behaviour: secret unset → pass through. Cookie valid → pass through. Query `hz=<secret>` correct and no valid cookie → `302` to the same path without `hz` plus `Set-Cookie`. Anything else → `401` with a plain-text body (no hint about the secret).

- [ ] **Step 1: Write failing tests**: `test_guard_disabled_without_secret`, `test_bootstrap_sets_cookie_and_redirects_without_the_secret_in_the_url` (also keeps other query parameters), `test_wrong_bootstrap_secret_is_401`, `test_missing_and_wrong_cookie_get_401_for_api_static_and_index`, `test_valid_cookie_reaches_the_api` (use `/api/health`), `test_cookie_flags` (HttpOnly, SameSite=Strict, Path=/), `test_pick_free_port_is_bindable`, `test_secret_is_long_and_unique`, `test_single_instance_second_acquire_fails_until_release`, `test_single_instance_lock_is_taken_over_after_release`, `test_wait_until_ready_times_out_and_succeeds` (local temporary HTTP server).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** and register `SessionGuard` in `main.py` as the outermost middleware (after `LocalRequestGuard`). **Step 4: Run** the full suite → PASS.
- [ ] **Step 5: Commit** `feat: desktop helpers and session guard`.

### Task 2: Native window launcher, icon, packaging

**Files:**
- Create: `requirements-desktop.txt` (`pywebview>=5; sys_platform == "win32"`), `scripts/make_icon.py`, `assets/horizon.ico`
- Modify: `backend/run_app.py` (desktop launcher), `scripts/build-exe.ps1` (`--noconsole`, `--icon`, pywebview hooks), `requirements-build.txt` (add `pillow`), `.github/workflows/ci.yml` only if needed (it must not require pywebview)

**Interfaces:**
- `run_app.main()`: acquire `SingleInstance(data_dir/"app.lock")` (if taken: message box "Horizon Events is already running." and exit 0); set `HORIZON_SESSION_SECRET`, `DATABASE_URL`, `HORIZON_MODEL_PATH`, `HORIZON_WATCH_DIR` defaults as today; start uvicorn with logging to `desktop.log` on a daemon thread; `wait_until_ready`; create the window at `http://127.0.0.1:<port>/?hz=<secret>`; `webview.start(storage_path=data_dir/"webview", private_mode=False)`; on window close set `server.should_exit = True`, join with a timeout, release the lock.
- `scripts/make_icon.py` draws a simple square mark (navy square, white shield or "H") at 16, 32, 48, 256 px into `assets/horizon.ico`; committed output, script kept for regeneration.

- [ ] **Step 1: Implement** the launcher and icon script; generate and commit the icon. Add a message-box helper (`ctypes.windll.user32.MessageBoxW`) used for the two error cases.
- [ ] **Step 2: Run from source** `python backend/run_app.py` with `requirements-desktop.txt` installed: confirm the window opens, shows the dashboard, and closing it ends the process.
- [ ] **Step 3: Update** `build-exe.ps1` (windowed, icon, `--collect-all webview` if the hook is not enough, hidden imports for `clr_loader` and `pythonnet`) and `README.md` (the app is now a desktop window; development still uses `uvicorn`).
- [ ] **Step 4: Run** the full backend suite and frontend tests → PASS (nothing in server mode changed).
- [ ] **Step 5: Commit** `feat: native desktop window launcher`.

### Task 3: Build and verify the executable

- [ ] **Step 1: Build** `dist\HorizonEvents.exe` and launch it with a temporary `LOCALAPPDATA`.
- [ ] **Step 2: Verify**: a process named HorizonEvents exists with the main window title `Horizon Events` and no console window; `desktop.log` names the port; a request to that port without the cookie returns 401 for `/`, `/api/health` and an asset; with the cookie (bootstrap URL) it returns 200; launching a second copy exits and leaves one process; closing the window leaves no process (`Get-Process` empty) and the lock is free (a third launch starts normally).
- [ ] **Step 3: Visual check**: capture the window's own pixels (PrintWindow through PowerShell, not a browser) to confirm the dashboard renders inside the native window. Do not commit this capture.
- [ ] **Step 4: Commit** any fixes found, with `docs` updated (`docs/security.md`: the session secret and what it protects against).
