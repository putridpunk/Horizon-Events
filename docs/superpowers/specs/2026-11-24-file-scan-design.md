# File scanning: design

**Goal.** In the desktop app the user picks files or folders ("annexes" them) and the app scans them for malware; every
detection becomes an alert.

**Approved approach (A).** Scan in place with Microsoft Defender's command line (`MpCmdRun.exe -Scan -ScanType 3
-File <path> -DisableRemediation`), report only: the app never deletes, moves or quarantines the user's files.
Rejected: our own signature engine (weak, misleading), online scanners such as VirusTotal (files leave the machine),
SHA-256 feed matching (the bundled feeds list IPs, not file hashes; revisit later).

**Non-goals.** Importing logs is unchanged and is not scanned. No remediation. No real-time protection. No scanning
in server/Docker mode (a server cannot see the user's files and has no native file picker).

**Behaviour.**
- A **Scan files** page (sidebar, "Respond") with two buttons, *Choose files* and *Choose folder*, which open the native
  Windows pickers through pywebview (`window.pywebview.api.pick_files / pick_folder`). Outside the desktop window the
  page says scanning is only available in the desktop app.
- `POST /api/scans {paths}` starts one background scan and returns it; only one runs at a time (409 otherwise).
  `GET /api/scans` lists recent scans, `GET /api/scans/{id}` is polled for progress, `GET /api/scans/status` says
  whether the feature is on and whether Defender is usable.
- Each path is scanned with its own Defender call. Per path the outcome is `clean`, `threat` or `error`. Defender
  missing/disabled/failing is shown as an error, never as "clean".
- Each detection stores an event (source `file_scan`, severity critical, metadata path/threat/sha256) and an alert
  from rule **HZ-008 Malware detected** (critical, MITRE T1204.002 Malicious File, tactic Execution). The alert key is
  the file hash (or path) plus threat name, so rescanning the same file does not raise duplicates while one is open.
- Paths must be absolute, exist, and not be UNC paths (`\host\share`), which would make Windows authenticate to a
  remote host. Quarantine by real-time protection is not an error: a file Defender already removed is simply gone.

**Testing.** Defender output and exit codes are parsed from recorded samples (no real malware, no EICAR on disk in the
repo; the EICAR string is only ever assembled in memory for a manual check).
