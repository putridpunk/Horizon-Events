# Desktop App and System Log Collection — Design

Date: 2026-11-23. Requested by the user: Horizon Events must integrate with the user's machine without the user attaching system logs, and must run locally as an application, not in a browser, so that no accounts are needed. Security log access: one-time setup (user's choice). Squarer UI corners are covered in `2026-11-23-corporate-ui-design.md`.

## Intent

Make Horizon Events a real desktop security monitor: open it, finish a short setup, and it reads this machine's own event logs continuously. Local-only, no accounts, no logins, no files to attach.

## This is three projects, built in this order

1. **Desktop shell:** a native window instead of a browser tab, with a per-launch session secret.
2. **System log collection:** live Windows Event Log (and Linux log files) collection with a setup flow and a Data sources page.
3. **Corporate UI:** the already-approved redesign (with the squarer corners), applied to everything including the new pages.

Each has its own plan and its own merge.

## Goals

- **Native window (Windows):** the `.exe` opens its own application window ("Horizon Events", own icon, minimum size) hosting the dashboard through the Microsoft WebView2 runtime (already installed on this machine). No console window, no browser tab, no visible URL.
- **Local-only, no accounts:** the server binds to `127.0.0.1` on a random free port. Each launch generates a random session secret; the window receives it once (a first-load request sets an `HttpOnly`, `SameSite=Strict` cookie) and every `/api` request must carry it. Another browser tab, page or local process cannot use the API without the secret. Server mode (Docker, development) is unchanged and keeps the Host and Origin guards.
- **Single instance:** a second launch brings the user's attention to the running one and exits, so two collectors never run at once.
- **Windows Event Log collection:** a background collector reads these channels (language-independent, via the built-in `wevtutil`) every 5 seconds, using the record ID as a bookmark so each event is read once, and feeds them through the existing pipeline (normalise, de-duplicate, detect, alert, correlate into incidents).

  | Channel | Needs | Events collected |
  | --- | --- | --- |
  | Security | Event Log Readers membership or admin | 4625 failed logon; 4624 successful logon (types 2, 7, 10, 11 only); 4740 lockout; 4720 account created; 4728, 4732, 4756 added to a privileged group |
  | System | none | 7031, 7034 service crashed |
  | Application | none | 1000 application crash |

  Noisy events (service and network logons, 4672 special privileges) are deliberately not collected. Event IDs outside this list are never read.
- **Start point:** collection starts from "now". The setup screen offers an optional backfill of the last 24 hours.
- **First-run setup:** a screen explains in plain language what is read and that everything stays on this machine, lets the user choose channels, and shows each one's state: **Collecting**, **Needs permission**, **Waiting for sign-out** or **Unavailable**.
- **One-time Security access:** an **Enable access** button (shown with an explanation and a confirmation) asks Windows, through its standard permission prompt, to add the current user to the built-in *Event Log Readers* group, identified by its well-known SID `S-1-5-32-573` so it works on any Windows language. Windows applies a new group membership only after the user signs out and in; the app shows **Waiting for sign-out** until the Security log becomes readable, then starts collecting automatically. Until then, System and Application collection still run.
- **Data sources page:** per-source status (state, last event time, events read, last error), enable and disable switches, a **Check access** action, and a clearly separated *Advanced* area for the existing watch folder and manual file import.
- **Linux (best effort):** the same collector framework reads fixed log files if present and readable (`/var/log/auth.log`, `/var/log/secure`, `/var/log/syslog`, `/var/log/messages`) through the existing tailer and parsers. It can only be tested here with sample files.

## Non-goals

macOS collection; a tray icon or background service (closing the window quits the app and stops collection in this version); an installer or auto-start; auditing-policy changes (the app reads what Windows already logs and says so when an event type is not being audited); Sysmon; remote machines.

## Anti-goals

Silent changes to the user's system: the group change happens only after an explicit click and Windows' own permission prompt. Reading anything beyond the listed channels and event IDs. Sending any log data off the machine. A browser fallback that quietly puts the UI back in a tab (if the native window cannot open, the app shows a clear message with the WebView2 download link instead).

## Approaches considered

- **Native window:** pywebview over WebView2 (chosen: one process, small, already supported by the machine); Edge in `--app` mode (still an Edge process and taskbar identity, depends on a browser); Electron or Tauri (heavy toolchains, a second runtime, a rewrite of the launcher).
- **Reading Windows logs:** `wevtutil` subprocess with XPath queries (chosen: built in, no dependency, language-independent XML); `pywin32` (extra dependency, same result); the raw `wevtapi` through `ctypes` (more code to maintain for no benefit at this volume).
- **Security log permission:** one-time Event Log Readers membership (chosen by the user); running as administrator on every launch (rejected: permission prompt every time).

## Design

### Desktop shell (`backend/run_app.py`, `backend/app/desktop.py`)

`run_app.py` picks a free port, creates a session secret, starts uvicorn on a daemon thread, waits until it answers, then opens a pywebview window at `http://127.0.0.1:<port>/?hz=<secret>`. A server-side middleware (active only when `HORIZON_SESSION_SECRET` is set) turns that first request into a cookie plus a redirect to `/`, and returns 401 for `/api` requests without the cookie. Closing the window stops the collectors and the server. Logs go to a file in the data folder (no console). PyInstaller builds a windowed executable with the app icon. A named Windows mutex enforces a single instance.

### Collectors (`backend/app/system/`)

- `base.py`: `Collector` interface (`id`, `name`, `describe()`, `status()`, `poll() -> int`), a `CollectorManager` thread (5 s interval, per-collector error isolation, pause and resume like the watch folder service) and persisted settings.
- `windows_eventlog.py`: `WindowsEventLogCollector(channel, event_ids, runner=run_wevtutil)`. It builds the XPath query (`*[System[(EventID=… or …) and (EventRecordID > N)]]`, with a `LogonType` condition for 4624), runs `wevtutil qe <channel> /f:xml /c:<n>` through an injectable runner, wraps the output in a root element, and hands it to `import_logs(session, "windows", "EventLog:<channel>", xml)`. The bookmark (last record ID per channel) is stored in the database after a successful import, so restarts neither re-read nor skip events. Access states come from the exit code and message of a one-record probe query.
- `access.py`: `security_access_state()`, `enable_security_access()` (the elevated `Add-LocalGroupMember -SID S-1-5-32-573 -Member <user>` command, launched through `ShellExecute` with the `runas` verb), group membership versus token check to tell **Needs permission** from **Waiting for sign-out**.
- `linux_logs.py`: collector over fixed log paths using `FileTailer`.
- Parser changes for real events (`processors/parser.py`, `collectors/windows.py`): keep `EventRecordID` and `Channel` in the raw text so events are unique and traceable; for 4728, 4732 and 4756 prefer `SubjectUserName` (who made the change) over the group name; keep unnamed `Data` values as `Data0`, `Data1` so the Application 1000 crash event yields the application name as the service. The existing sample files and imports keep working.
- Tables: `collector_settings` (collector id, enabled, backfill requested, last record ID, last activity, last error). Created automatically.
- API: `GET /api/collectors`, `PATCH /api/collectors/{id}` (`enabled`, `backfill_hours`), `POST /api/collectors/security/enable-access`, `POST /api/collectors/{id}/check`. Setup state (`setup_completed`) in `GET /api/setup` and `POST /api/setup/complete`. State-changing calls keep the existing Origin guard.

### Frontend

A first-run **Setup** screen (shown until completed) and a **Data sources** page; both use the corporate styling from the UI design. The existing "Live monitoring" watch-folder card moves under Data sources, Advanced.

## Testing

- **Collectors:** XPath query building for each channel and the 4624 logon types; a fake runner returning fixture XML (real-shaped events for each collected ID) to check parsing, bookmarks, restart behaviour, de-duplication and failure isolation; access-state mapping from exit codes (including the Portuguese "Acesso negado" text, by relying on exit codes, not messages); the elevation command string (never executed in tests); Linux collectors against temporary files.
- **Real machine, read-only:** an opt-in test that runs the real `wevtutil` against the System channel (readable without permission) and checks only structure, never content. The Security collector and the group change are verified against fixtures only. I will not run the elevated command; the user clicks Enable access themselves.
- **Desktop:** session-secret middleware (cookie issued once, 401 without it, bypass when the variable is unset), single-instance guard logic, free-port selection; the native window itself verified by launching the built executable.
- **API and UI:** collector endpoints, setup flow states, Data sources page rendering in each state.

## Left to the builder

Window default size and icon artwork, the wording of setup text beyond what is specified, and polling batch sizes, within the limits above.
