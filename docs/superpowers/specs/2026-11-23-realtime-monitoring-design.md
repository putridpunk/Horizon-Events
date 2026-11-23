# Real-time Monitoring (Milestone 5, part 3) — Design

Date: 2026-11-23. Approved in conversation ("watch folder, go").

## Intent

Ingest logs continuously instead of only through manual imports: drop or append to files in a watch folder and events, alerts and the dashboard update on their own. Portfolio feature: safe, restart-tolerant, demonstrable in one terminal command.

## Goals / non-goals

- Goals: one watch folder; the subfolder name selects the parser (`linux_auth`, `linux_syslog`, `windows`, `application`, `json`); a background poller (2 s) ingests only new, complete lines through the existing `import_logs`; status and pause/resume in the API and on the Overview page; works in local runs, the executable and Docker.
- Non-goals: arbitrary file paths, network syslog listener, tailing XML/CSV/JSON-array files (they cannot be read line by line), persistent offsets, WebSocket push (the dashboard polls).
- Anti-goals: reading files outside the watch folder; a bad file stopping the watcher; duplicate events or alerts after a restart.

## Approaches considered

- **Watch folder, polling thread (chosen):** simple, portable (Windows, Linux, Docker bind mounts), no new dependencies.
- **OS file-event library (watchdog):** extra dependency; unreliable on Docker bind mounts. Rejected.
- **Arbitrary registered paths:** lets the app read any file on disk. Rejected by the user.

## Design

- `backend/app/watcher/tailer.py` (pure, no DB): `FileTailer` keeps one `offset` per file. `read_new(path, max_bytes=1_048_576) -> bytes` returns only complete lines after the offset and advances past the last newline, so a half-written line waits for the next poll. If the file is smaller than the offset (truncated or rotated) the offset resets to 0. Missing files return `b""`.
- `backend/app/watcher/service.py`: `WatchService(watch_dir, session_factory, interval=2.0)`. `scan_once()` creates the source subfolders if needed, visits direct regular-file children of each known subfolder (symlinks and other subfolders ignored), tails each file and calls `import_logs(session, source_type, filename, bytes)`. Per-file counters (`lines`, `imported`, `alerts`, `last_activity`, `last_error`). Errors are recorded per file and never stop the loop. `start()` / `stop()` run a daemon thread; `pause()` / `resume()`; `status()`.
- Line-oriented source types only: `windows` accepts JSON Lines in the watch folder; XML, CSV and JSON arrays should be imported manually. Files that fail to parse are counted as skipped lines.
- Offsets are kept in memory. After a restart the files are read again from the start; the event fingerprint prevents duplicate events and alerts, at the cost of re-parsing.
- Wiring: the API lifespan starts the service when `HORIZON_WATCH_DIR` is set. `GET /api/watcher/status`, `POST /api/watcher/pause`, `POST /api/watcher/resume` (status reports `enabled: false` when not configured). The launcher defaults the folder to `%LOCALAPPDATA%\HorizonEvents\watch` and prints it. Docker mounts `./watch` at `/watch`.
- Frontend: a "Live monitoring" card on Overview (state, folder, files table with source type, lines and last activity, Pause/Resume).
- Security: only direct children of known subfolders are read; symlinks are skipped; each read is capped per poll; paths shown in the UI are relative to the watch folder.

## Testing

Tailer: appends only, partial line held, truncation resets, per-poll cap, missing file. Service: ingest and alert across two appended batches (HZ-001 after the second), unknown subfolder ignored, symlink ignored when creatable, pause stops ingestion and resume continues, a failing file does not stop others, restart does not duplicate events. API: disabled status, enabled status, pause/resume. Thread smoke test: start, append, event appears within a few seconds, stop.

## Left to the builder

Card layout, exact status field names beyond those listed, and thread shutdown details.
