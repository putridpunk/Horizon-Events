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

The local names are `localhost`, `127.0.0.1` and `::1`. Requests without an `Origin` header (curl, scripts) are not browser-driven and are allowed.

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
