# HORIZON EVENTS

**Security Information and Event Management** · *Turning security events into actionable intelligence.*

[![CI](https://img.shields.io/github/actions/workflow/status/putridpunk/Horizon-Events/ci.yml?branch=main&label=CI&logo=github)](https://github.com/putridpunk/Horizon-Events/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/putridpunk/Horizon-Events?label=release&color=orange)](https://github.com/putridpunk/Horizon-Events/releases/latest)
[![licence](https://img.shields.io/badge/licence-MIT%20(non--commercial)-blue)](LICENSE)
[![python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)](#quick-start-local)
[![platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D4?logo=windows&logoColor=white)](#windows-desktop-app)
[![detection](https://img.shields.io/badge/detection-MITRE%20ATT%26CK-red)](docs/detection-rules.md)
[![network](https://img.shields.io/badge/network-local%20only-brightgreen)](docs/security.md)

Horizon Events is a lightweight SIEM. It imports logs from Linux and Windows systems and applications, normalises them into one event format, runs configurable detection rules, raises alerts with a full status history, and presents everything in an interactive dashboard (light by default, with a dark theme). Reports export to JSON, CSV and HTML.

Built with Python, FastAPI, SQLAlchemy (SQLite), React, Chart.js and Docker. All bundled data is synthetic.

## Screenshots

All data below is synthetic, produced by the bundled sample logs.

**Overview**: key counts, a Needs attention list of the alerts and incidents to look at first, and events over time. Light by default, with a dark theme one click away.

![Overview dashboard](docs/screenshots/overview.png)

![Overview in the dark theme](docs/screenshots/overview-dark.png)

**Alert detail**: MITRE ATT&CK techniques, the investigation workflow, history and the events behind the alert. The "Known malicious" badge comes from a threat feed, matched locally.

![Alert detail drawer](docs/screenshots/alert-drawer.png)

**Incident**: related alerts grouped by shared IP or account, with an audit trail.

![Incident detail drawer](docs/screenshots/incident-drawer.png)

**Analytics**: distributions, MITRE ATT&CK coverage, the anomaly model (HZ-007), threat feeds and per-rule statistics.

![Analytics](docs/screenshots/analytics.png)

<details>
<summary>More: event feed and reports</summary>

![Event monitoring](docs/screenshots/events.png)

![Reports](docs/screenshots/reports.png)

</details>

## Architecture

```
LOG SOURCES -> COLLECTION -> NORMALISATION -> DETECTION ENGINE -> DATABASE -> ALERT MANAGEMENT -> DASHBOARD
```

- `collectors/` read Linux auth/syslog, Windows events (XML/JSON/CSV exports), application logs and custom JSON.
- `processors/` parse each format and normalise it to a common `Event`.
- `detection/` is a pure-Python, rule-based engine. It has no FastAPI or database imports and reads history through a small `EventHistory` protocol, so a future ML detector can implement the same `Rule` interface.
- `alerts/` creates, de-duplicates and tracks alerts (Open, Investigating, Resolved) with history.
- `database/` holds SQLAlchemy models and repositories, the only code that issues queries. SQLite today; `DATABASE_URL` is the seam for PostgreSQL.
- `api/` are thin FastAPI routers over `services/`.

See [docs/architecture.md](docs/architecture.md), [docs/detection-rules.md](docs/detection-rules.md) and [docs/api.md](docs/api.md).

## Quick start (Docker)

```bash
docker compose up --build
```

Open http://localhost:8080. The sample logs are imported automatically on first start (set `SEED_ON_START=false` to disable).

## Quick start (local)

Backend (Python 3.11+):

```bash
python -m venv .venv
.venv/Scripts/activate        # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
cd backend
python -m app.seed            # optional: import the sample logs
uvicorn app.main:app --reload
```

Frontend (Node 20+):

```bash
cd frontend
npm install
npm run dev                   # http://localhost:5173, proxies /api to localhost:8000
```

## PostgreSQL

SQLite is the default. To run on PostgreSQL, either set `DATABASE_URL=postgresql+psycopg://user:password@host:5432/dbname` for a local run, or use the compose override:

```bash
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up --build
```

The override starts PostgreSQL 16 (not published to the host) and points the backend at it; set `POSTGRES_PASSWORD` for anything beyond local use. The whole test suite also runs against PostgreSQL: set `HORIZON_TEST_DATABASE_URL` to a throwaway database (the schema is recreated for every test) and run `python -m pytest`. CI runs the suite on both databases.

## Windows desktop app

`dist\HorizonEvents.exe` is a single-file desktop application. It opens **its own window** (using the Microsoft Edge WebView2 runtime that ships with Windows 10 and 11) rather than a browser tab, so there is nothing to sign in to. Closing the window quits the app. Only one copy runs at a time: starting it again brings the open window to the front.

- **Local only.** The server listens on `127.0.0.1` on a random port, and every launch creates a one-time secret that only the app's own window receives. No other browser tab or program can use the API. See [docs/security.md](docs/security.md).
- **Your data** lives in `%LOCALAPPDATA%\HorizonEvents` (database, model, watch folder and `desktop.log`). The app starts empty. To explore with the bundled sample logs, set the environment variable `HORIZON_SEED=true` before the first launch.
- If the window cannot open, the app tells you and links to the WebView2 runtime; it never falls back to a browser tab.

Run it from source (needs `requirements-desktop.txt` and a built frontend):

```powershell
pip install -r requirements.txt -r requirements-desktop.txt
cd frontend; npm install; npm run build; cd ..
python backend\run_app.py
```

Rebuild the executable (also needs `requirements-build.txt`):

```powershell
pip install -r requirements-build.txt
powershell -File scripts\build-exe.ps1
```

### Installer

Download `HorizonEvents-Setup.exe` from the [latest release](https://github.com/putridpunk/Horizon-Events/releases/latest) (checksums are in `SHA256SUMS.txt`; the installer is unsigned, so Windows SmartScreen may warn: choose *More info > Run anyway*). Releases are built by GitHub Actions when a `v*` tag is pushed; if the repository secrets `SIGN_PFX_BASE64` (a base64-encoded code-signing `.pfx`) and `SIGN_PFX_PASSWORD` are set, the executable and installer are signed too. It is a standard Windows installer. It installs for the current user (no administrator rights; an all-users install is offered in the first dialog), lets you tick **Desktop shortcut** and **Start menu shortcut** independently, and can launch the app when it finishes. Horizon Events then appears in **Settings > Apps > Installed apps** (Control Panel > Programs and Features), where **Uninstall** removes it. Uninstalling removes everything: the program, its shortcuts, the start-with-Windows entry, the data in `%LOCALAPPDATA%\HorizonEvents` (events, alerts, settings, quarantine, logs) and any Windows Firewall rules the app added (one Windows permission prompt, only if there are such rules). Backups you saved elsewhere are not touched. If Horizon Events is running, even hidden in the tray, the uninstaller stops with an error and removes nothing: quit the app first.

Build it after the executable (needs [Inno Setup 6](https://jrsoftware.org/isinfo.php), `winget install JRSoftware.InnoSetup`):

```powershell
powershell -File scriptsuild-installer.ps1
```

For development, run the API as a server instead with `uvicorn app.main:app` from `backend/` and the Vite dev server in `frontend/`.

## Scanning files for malware

**Scan files** (sidebar, under Respond) checks files and folders you choose for malware. In the desktop app, *Choose files* and *Choose folder* open the normal Windows pickers; each item is scanned where it is by **Microsoft Defender** on your computer (`MpCmdRun.exe`, report-only), and every detection becomes a critical alert from rule **HZ-008 Malware detected** (MITRE ATT&CK T1204.002), with the threat name and, when the file can still be read, its SHA-256.

- Nothing is uploaded, moved, quarantined or deleted by Horizon Events. Defender's own real-time protection may still act on a file by itself.
- A scan runs in the background; the page shows progress, per-item results and earlier scans. Only one scan runs at a time.
- If Defender is missing or fails, the item is reported as *Could not scan*, never as clean. This is a second opinion from the engine Windows already provides, not a replacement for antivirus software.
- Only available in the desktop app: a server or Docker install cannot see your files. Network (`\\host\share`) paths are refused.

## Everyday use

All of these are in **Settings** (sidebar, Configure) in the desktop app:

- **Running in the background.** A tray icon is always shown. Optionally keep the app running there when the window is closed (Quit from the tray icon stops it), get a Windows notification for new critical (or high) alerts, and start Horizon Events when you sign in to Windows (it then opens hidden in the tray). Only alerts raised after the app started are announced.
- **Scan new downloads.** Off by default. Each new file in your Downloads folder (or another folder) is scanned with Microsoft Defender once it has finished downloading; files already there are not scanned.
- **Data.** Delete events older than a chosen period (events that belong to an alert are always kept) and make a backup of all your data, or restore one. A restore is applied the next time the app starts and the previous database is kept next to it as `horizon.db.before-restore`. Backups need the built-in SQLite database.
- **Suppressed alerts.** In an alert's detail panel, *Suppress similar alerts* hides future alerts for the same rule, address and account (malware detections cannot be suppressed). Settings lists what is suppressed, how many alerts each silenced, and lets you remove it.
- **Language.** English, Português, Français, Español, Deutsch, Italiano, Polski, Русский, Ελληνικά, 中文（简体）, 日本語, 한국어 and العربية (laid out right to left). *Automatic* follows the Windows language and falls back to English. Screens, alert recommendations and rule names are translated; events, log lines, error messages from the server and MITRE technique names stay as they are. Each language is a small file loaded only when chosen (`frontend/src/i18n/langs/`); a missing text simply stays English, and tests check that every language is complete. The translations were written by an AI and have not been reviewed by native speakers, so corrections are welcome.

## Responding to alerts

Every alert shows **Recommended steps** in plain language (rule by rule, in `backend/app/mitigation/advice.py`). In the desktop app the app can also carry out two of them, under **Mitigation** (sidebar, Respond):

- **Block an attacking address** (rules HZ-001, HZ-003, HZ-006; never the ML rule HZ-007). You approve it in the app and Windows then asks for administrator permission once; the app adds an inbound Windows Firewall rule named `Horizon Events block <ip>` and checks that it exists. *Remove block* undoes it. Nothing keeps administrator rights, so blocks are never automatic. Private-network addresses, this computer's own addresses and your allowlist are never blocked (private ones can be allowed in settings). A block gets a reminder date (default 7 days); expired blocks are flagged for removal.
- **Quarantine malware** (rule HZ-008). The flagged file is moved, not deleted, into `%LOCALAPPDATA%\HorizonEvents\quarantine` and can be restored; no administrator rights needed. Modes per action: *Off*, *Ask first* (default) or, for quarantine only, *Automatic* (right after a scan finds it).

Every proposal and action is kept in the history with its outcome. Files in the Windows folder are never moved.

## Collecting this computer's own logs

In the desktop app, Horizon Events reads the machine's own event logs, so you never attach files. A first-run screen explains what is read and lets you choose; everything stays on this computer.

| Source | What is collected | Permission |
| --- | --- | --- |
| Windows Security log | failed and successful sign-ins (interactive, unlock, remote and cached), account lockouts, new accounts, changes to privileged groups | one-time setup, see below |
| Windows System log | services that crash or stop unexpectedly | none |
| Windows Application log | applications that crash | none |
| Linux `auth.log` / `secure`, `syslog` / `messages` | same detections as imported Linux logs | read access to the file |

Only these event IDs are read (Security 4625, 4624 for logon types 2, 7, 10 and 11, 4740, 4720, 4728, 4732, 4756; System 7031, 7034; Application 1000). Noisy events such as service logons are deliberately skipped. Collection starts from "now"; the setup screen can also read the last 24 hours. Closing the window stops collection.

**Security log access.** Windows protects this log. The **Enable access** button asks Windows (through its normal permission prompt) to add your account to the built-in *Event Log Readers* group. Nothing changes unless you approve it, and you can remove yourself from the group at any time. Windows only applies a new group membership after you sign out and back in once; until then the Security source shows *Waiting for sign-out* and the System and Application logs keep working. The **Data sources** page shows every source, its state, how many events it has read and the last error.

Windows must be auditing the events for them to exist: sign-in auditing is on by default, other categories may need to be enabled in the local security policy.

## Live monitoring (watch folder, advanced)

Set `HORIZON_WATCH_DIR` (the executable defaults to `%LOCALAPPDATA%\HorizonEvents\watch`; Docker mounts `./watch`) and Horizon Events ingests new log lines continuously. The **subfolder name selects the parser**:

```
watch/
  linux_auth/auth.log      linux_syslog/syslog.log     application/app.log
  windows/events.jsonl     json/custom.jsonl
```

Append lines (for example with `Add-Content` or a log shipper) and events, alerts and the dashboard update within a few seconds. Only complete lines are read, files that shrink are re-read from the start, and re-reading a file never creates duplicate events. Limits: only line-oriented files can be tailed (Windows logs as JSON Lines; XML, CSV and JSON arrays are imported manually), only direct children of the known subfolders are read, and symlinks are ignored. The Overview page has a Live monitoring card with Pause and Resume.

## Threat intelligence

Alerts show a **Known malicious** badge when their source IP is on a threat feed. Matching happens locally against downloaded lists, so no IP from your logs is ever sent anywhere. The only network action is the **Refresh feeds** button on the Analytics page, which downloads:

- [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/blocklist/) botnet C2 IPs (CC0), and
- [Spamhaus DROP](https://www.spamhaus.org/drop/) netblocks (free use under Spamhaus's terms; fetched at most once an hour, which the app enforces).

Private and loopback addresses are never checked. A small **synthetic demo feed** (clearly labelled, covering the reserved test addresses used in `sample_logs/`) is loaded with the sample data so the badge shows offline; it is not real intelligence. Per-IP lookup services such as AbuseIPDB are not used because they would send your log data to a third party.

## Incidents

Related alerts are grouped into **incidents** automatically, so you investigate one story instead of many alerts. A new alert joins the lowest-numbered open incident that has an alert with the same source IP or the same account, with activity within 24 hours; otherwise it opens a new incident. Alerts with neither an IP nor an account are not grouped. Incident severity is the highest of its alerts.

On the **Incidents** page you can start an investigation, resolve or reopen an incident, add notes, rename it, remove an alert (it will not be regrouped), or merge incidents. Every change is recorded in the incident's audit trail. An incident's status is separate from its alerts' statuses: resolving an incident does not resolve its alerts. An incident means "investigate these together", not that a breach is confirmed.

## What the sample data demonstrates

`sample_logs/` tells a small story across sources:

| Activity | Rule |
| --- | --- |
| 12 failed SSH logins for `admin` from `192.168.1.15`, then a success | HZ-001 (critical) |
| An after-hours login by `alice` at 23:40 | HZ-002 |
| Four attempts against nonexistent accounts from `203.0.113.7` | HZ-003 |
| `sudo` to root by `bob`; a group change by `tmp_contractor` | HZ-004 |
| `nginx` failing four times; the Windows Spooler service failing | HZ-005 |
| Account lockouts on Linux (`admin`) and Windows (`jsmith`) | HZ-006 |
| A slow password spray (3 attempts an hour, different usernames) from `198.51.100.77` | HZ-007 (ML) |

You can also import your own files from the dashboard's **Import logs** button (choose the matching source type). Re-importing a file does not create duplicates.

## Testing

```bash
cd backend
python -m pytest
```

The suite covers the parsers, collectors, rules, alert manager, repositories, ingestion, statistics, reports and the API.

Frontend tests use [Vitest](https://vitest.dev) and React Testing Library with the API mocked:

```bash
cd frontend
npm test
```

They cover the API client and polling hook, the alert and incident drawers (status workflows, notes, merging, error messages), the list pages and their filters, the live-monitoring, threat-feed and anomaly-model cards, report date handling, and the empty-database screens. The Chart.js charts are stubbed because jsdom has no canvas.

## Security

The API has no login, so Horizon Events is built to be used from the machine it runs on: the executable and the Docker setup listen on `127.0.0.1` only, and the server refuses requests with an unknown `Host` (DNS rebinding) or a foreign `Origin` on state-changing calls (cross-site forgery). Read [docs/security.md](docs/security.md) for what is and is not protected and how to expose it safely behind an authenticating proxy (`HORIZON_BIND`, `HORIZON_ALLOWED_HOSTS`).

## Limitations

- Syslog lines carry no year or timezone; Horizon Events assumes the current year and treats times as UTC.
- Windows support is for exported event logs, not live collection.
- The dashboard polls (every 5-10 seconds) instead of using a push channel.
- Alerts flag *suspicious activity*, not confirmed breaches.

## Roadmap

Done in milestone 5 so far: ML anomaly detection (rule HZ-007, Isolation Forest over per-IP hourly activity; see [docs/detection-rules.md](docs/detection-rules.md)). MITRE ATT&CK mapping (rules and alerts tagged with techniques, coverage panel, report section). Real-time monitoring (a watch folder is tailed continuously; see below). Threat intelligence enrichment (blocklist feeds matched locally; see below). Incident management (alerts grouped into incidents; see below). Milestone 5 is complete.

## Licence

Released under the [MIT Licence, modified](LICENSE): you may not distribute, resell or earn income from this software without first getting permission from [putridpunk](https://github.com/putridpunk). The sample logs are synthetic. Threat feed data downloaded at runtime stays under its providers' terms (abuse.ch Feodo Tracker is CC0; Spamhaus DROP has its own terms of use).
