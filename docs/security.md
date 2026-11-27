# Security model

Horizon Events is a **local analysis tool**. It stores security logs and exposes a REST API **without authentication**. It is designed to be reached from the machine it runs on, and its defaults assume that.

## What is protected

| Risk | Protection |
| --- | --- |
| Network exposure of the unauthenticated API | The executable binds to `127.0.0.1`. Docker publishes the dashboard on `127.0.0.1:8080` only (the backend and PostgreSQL are never published). |
| A web page in your browser driving the API (cross-site request forgery) | State-changing requests (`POST`, `PATCH`, `PUT`, `DELETE`) whose `Origin` header is not a local name are refused with 403. This matters because some cross-site requests, such as a plain form upload to `/api/imports` or a bodyless `POST /api/watcher/pause`, need no CORS preflight. |
| A web page reading the API through DNS rebinding | Requests whose `Host` header is not a local name are refused with 400. |
| Malicious log content | XML is parsed with `defusedxml` (no external entities or entity expansion); SQL goes through SQLAlchemy parameters; parsers never evaluate input; imports are size-capped. |
| Cross-site scripting | React escapes all rendered values and no raw HTML is injected; the HTML report escapes every value. |
| Feed downloads | Feed URLs are constants (https only), responses are size-capped, matching is local so no log IP leaves the machine, and nothing is downloaded unless you click Refresh. |
| Watch folder | Only direct, regular (non-symlink) files in the known source subfolders are read. |

**Desktop app.** The Windows executable adds a per-launch session secret. Each launch generates a random secret (`secrets.token_urlsafe(32)`) that only the app's own window receives, in its first request. The server turns it into an `HttpOnly`, `SameSite=Strict` cookie, redirects to the same address without the secret, and answers **401** to every other request, including pages, static files and the API. A browser tab, another program, or a malicious page therefore cannot use the server even though it can reach the port. The server listens on `127.0.0.1` on a random port, the secret is never written to the log (the access log is off), and a lock file keeps a second copy from starting. This is why the desktop app needs no accounts. Server mode (Docker, `uvicorn`) does not use the secret and relies on the Host and Origin checks above.

The local names are `localhost`, `127.0.0.1` and `::1`. Requests without an `Origin` header (curl, scripts) are not browser-driven and are allowed.

## System log collection

- Only a fixed list of event IDs is read, from three Windows channels (or fixed Linux log files). Nothing is sent anywhere.
- Reading the Security log needs the user's own approval: the app only *asks Windows* to add the user to Event Log Readers, shows exactly what will happen first, and Windows shows its own permission prompt. The command is built from the user's SID (no names are pasted into a command line) and run by Windows, not by the app.
- Windows tools are started by full path from the system folder, without a shell or console window.
- Collected events contain what Windows records: account names, host names and IP addresses. They are stored unencrypted in the local database, like all other data.

## File scanning

- Scanning reads only the paths the user picked in the native Windows dialog, and runs Microsoft Defender in report-only mode (`-DisableRemediation`); nothing is uploaded, moved or deleted by this app.
- The API accepts only absolute, existing, local paths (at most 50 per scan). UNC (`\\host\share`) and device paths are refused, because opening them would make Windows authenticate to the host the path names.
- The tool is started by full path, without a shell. The verdict comes from Defender's own summary, and any failure is reported as an error, never as "clean".
- The scan endpoints exist only in the desktop app (`HORIZON_FILE_SCAN=1`) and, like the rest of the API, only answer the app's own window.

## Mitigation

- Only two actions exist: add or remove one Windows Firewall rule, and move or restore one file. Nothing is deleted.
- Blocking needs administrator rights and is never automatic: each block or removal is approved in the app and then confirmed in Windows' own permission prompt; the app holds no standing privileges and has no privileged helper. Success is checked by reading the rule back, not from an exit code.
- The command line is built only from an address parsed by `ipaddress` (no user text reaches it) and runs `netsh.exe` by full path, without a shell.
- Safeguards: no private-network, loopback, multicast or reserved addresses (private ones only if the user allows it), never this computer's own addresses, a user allowlist, and no action from the statistical rule HZ-007.
- Quarantine moves only the path Defender reported for an HZ-008 alert, never from the Windows folder, never overwrites on restore.
- The endpoints that act exist only in the desktop app (`HORIZON_MITIGATION=1`) and, like the rest of the API, answer only the app's own window.

## Background mode, backups and downloads

- The tray icon, notifications and start-with-Windows need no administrator rights. Starting with Windows writes one per-user entry (`HKCU` Run key, value `HorizonEvents`) that launches the installed program with `--background`; it is refused when running from source.
- Backups are written only to an absolute local path ending in `.hzbackup` (never a UNC path), and an existing file is overwritten only if it is itself a database, so the API cannot be used to overwrite arbitrary files. A restore must contain Horizon Events tables, is staged and applied at the next start, and the previous database is kept.
- Watching the Downloads folder only reads file names, sizes and modification times, then hands finished files to the same report-only Defender scan. It is off by default.
- Updating the installed app stops a running copy first (`taskkill`), because in background mode closing the window only hides it. **Uninstalling does not**: while the app runs (it holds the named marker `HorizonEvents.Running`) the uninstaller shows an error and removes nothing, so the user decides when to quit.
- Uninstalling then runs `HorizonEvents.exe --uninstall-cleanup`, which deletes only a folder named `HorizonEvents` (never any other path), removes the start-up entry and, with one Windows permission prompt and only if any exist, the firewall rules named `Horizon Events block ...` (found by name, so it works in any Windows language).

## Notifications and scheduled reports

- Horizon Events sends nothing anywhere until you add a notification channel. A channel sends the alert's rule, description, source address, account and counts to the webhook, Slack, Discord or mail server **you** entered, and nothing else. Treat those services as places your log data may be stored.
- Webhook, Slack and Discord addresses and mail passwords usually contain secrets. They are stored in the database (a backup contains them) and are never returned by the API, which shows only the host and whether a value is set. Slack and Discord addresses must use `https`.
- A webhook with a signing secret carries an `X-Horizon-Signature: sha256=<hmac>` header (HMAC-SHA256 of the request body) so the receiver can check where a message came from.
- The API can be asked to contact any `http(s)` address you give it, from this computer. This is why the API must stay reachable only by you (see below).
- Scheduled reports are written only to the reports folder (`HORIZON_REPORT_DIR`, default `reports` next to the data) under generated names; the API cannot choose a path. The latest 30 files per schedule are kept.

## What is not protected

- **There is no login.** Anyone who can reach the API can read every event, change alert and incident status, tune rules, import logs and pause live monitoring. Keep it on localhost or behind something that authenticates.
- **The model file is a pickle** (`joblib`). The app writes it to its own data folder (`HORIZON_MODEL_PATH`). Never point that variable at a file you did not create: loading an untrusted pickle can run arbitrary code.
- **The PostgreSQL override ships a development password** (`horizon`, via `POSTGRES_PASSWORD`). The database is not published to the host, but set your own password for anything beyond local use.
- **The Windows executable is not code-signed**, so Windows SmartScreen will warn when you run it.
- **Log data is stored unencrypted** in SQLite or PostgreSQL. Protect the data folder or volume as you would the logs themselves.
- **Imported logs are untrusted input, but their content is shown in the UI.** An attacker who can write to a monitored log can influence what appears in alerts and events (for example usernames); the UI escapes it but cannot tell whether it is true.

## Exposing it beyond localhost

Do this only behind a reverse proxy or gateway that authenticates users.

1. Publish the port: `HORIZON_BIND=0.0.0.0 docker compose up` (or a specific interface address).
2. Allow the hostname users will type, so the Host and Origin checks accept it: `HORIZON_ALLOWED_HOSTS=siem.example.com`.
3. Terminate TLS and require authentication at the proxy.

## Reporting a problem

This is a portfolio project. If you find a vulnerability, open an issue on the GitHub repository without including exploit details for real systems.
