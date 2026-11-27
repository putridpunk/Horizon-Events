# Detection rules

Rules are stored in the `detection_rules` table and can be changed through `PATCH /api/rules/{id}` (`enabled`, `severity`, `params`). Parameters are merged with the defaults below.

| ID | Name | Event types | Default behaviour | Parameters |
| --- | --- | --- | --- | --- |
| HZ-001 | Repeated login failures | `authentication_failure` | At least 5 failures from one source IP within 5 minutes is **high**; 10 or more is **critical** | `threshold`, `critical_threshold`, `window_minutes` |
| HZ-002 | Unusual login hours | `authentication_success` | A successful login before 08:00, from 18:00, or on a weekend is **medium** | `work_start`, `work_end`, `weekends` |
| HZ-003 | Unknown users | `unknown_user` | One attempt is **medium**; 3 or more from one IP within 5 minutes is **high** | `ip_threshold`, `window_minutes` |
| HZ-004 | Privilege escalation events | `privilege_escalation` | Any escalation by an account not on the allowlist is **high** | `allowlist` |
| HZ-005 | Service failures | `service_failure` | 3 failures of one service within 10 minutes is **medium** | `threshold`, `window_minutes` |
| HZ-006 | Account lockouts | `account_lockout` | Any lockout is **high** | none |
| HZ-007 | Anomalous IP activity | all | ML rule: an Isolation Forest scores each source IP's hourly activity against a learned baseline. Outliers are **medium**, the most extreme **high**. Needs a trained model; without one the rule stays silent | `min_events` |
| HZ-008 | Malware detected | file scan | Raised by **Scan files**, not by the log engine: Microsoft Defender reported a threat in a file or folder you scanned. Always **critical**; one alert per file (hash or path) and threat | none |
| HZ-009 | Audit log cleared | `log_cleared` | A Windows event log was cleared (events 1102 or 104). Always **critical** | none |
| HZ-010 | New service installed | `service_installed` | A service was installed (events 7045 or 4697). **Medium**; one alert per service name | `ignore` (service-name prefixes to skip) |
| HZ-011 | Scheduled task created | `scheduled_task_created` | A task was created (event 4698). **Medium**; one alert per task. Tasks under the Microsoft folder are ignored by default | `ignore` (task-name prefixes to skip) |
| HZ-012 | Remote desktop logon | `remote_login` | A successful sign-in through Remote Desktop (logon type 10). **Medium**, **high** when it came from a public address | none |
| HZ-013 | Logon with explicit credentials | `explicit_credentials` | 3 or more explicit-credential logons (event 4648) by one account within 10 minutes is **medium** | `threshold`, `window_minutes` |
| HZ-014 | NTLM network logon | `ntlm_logon` | A network sign-in over NTLM from a public address, by a person's account (not a machine or anonymous): **high** | `ignore_private` |
| HZ-015 | New local administrator | `privilege_escalation` | An account added to Administrators (**high**) or Domain/Enterprise Admins (**critical**) | `groups` |
| HZ-016 | Suspicious PowerShell | `powershell_script` | A script block (event 4104) containing a keyword such as an encoded command or a download: **high** | `keywords` |
| HZ-017 | External device connected | `usb_device` | A new external device was recognised (event 6416): **low**; one alert per device | `ignore` |
| HZ-018 | Sign-in from a new country | `authentication_success`, `remote_login` | An account signs in from a country it has not used in the last 90 days (and has signed in before): **medium**. **Needs a location database.** | `lookback_days`, `min_history`, `ignore_countries` |
| HZ-019 | Impossible travel | `authentication_success`, `remote_login` | Two sign-ins by one account too far apart for the time between them (over 500 km at over 900 km/h; or, with no coordinates, a different country within an hour): **high**. **Needs a location database.** | `window_hours`, `max_speed_kmh`, `min_distance_km`, `country_change_hours` |

Windows event IDs recognised: 4624 (success; logon type 10 is Remote Desktop, type 3 with NTLM is an NTLM network logon), 4625 (failure; sub-status `0xC0000064` means unknown user), 4648 (explicit credentials), 4740 (lockout), 4672/4728/4732/4756 (privilege), 4697/7045 (service installed), 4698 (task created), 1102/104 (log cleared), 4104 (PowerShell script block), 6416 (external device), 7031/7034 (service failure).

An alert means *suspicious activity worth investigating*, not a confirmed breach.

## HZ-007: how the anomaly model works

- **Unit:** one source IP in one hour. Events without an IP are ignored.
- **Features:** `events`, `failures`, `successes`, `distinct_users`, `distinct_failed_users`, `failure_ratio`, `off_hours`.
- **Model:** scikit-learn `IsolationForest` (200 trees, `random_state=42`, contamination 1%). Windows with fewer than `min_events` events are never scored.
- **Explanations:** the alert names the features that deviate most from the baseline, e.g. `failures 3 (typical 0.2)`.
- **Merging:** all flagged hours for one IP in an import become a single alert.
- **Training:** `POST /api/ml/train` (`synthetic` or `database`), `python -m app.ml.train --source synthetic|database`, or the card on the Analytics page. The synthetic baseline is 21 days of generated normal activity (workstations, a few shared gateways, occasional forgotten passwords). Training on your own data needs at least 50 per-IP hourly windows.
- **Demo:** `sample_logs/slow_spray.log` is a password spray of three attempts per hour with different usernames from `198.51.100.77`. No threshold rule fires on it, but HZ-007 does.
- **Limits:** the model learns whatever is "normal" in its training data, so training on data that already contains attacks teaches it to accept them. Treat alerts as leads to investigate.

## Rules of your own

Open **Detection rules** in the sidebar. A rule is a set of conditions over an event's fields (`event_type`, `severity`, `username`, `source_ip`, `host`, `service`, `source`, `message`, `raw`), combined with *all of / any of / not*, plus how many matches in how many minutes it takes to raise an alert and what to count separately for (`none`, `source_ip`, `username`, `host`, `service`). Tests: is, is not, contains, does not contain, starts with, ends with, is one of, matches a pattern (`*`), is in an address block, severity at least/at most, is present, is missing, and (for Windows events) a named raw field. Your rules are called `CR-001`, `CR-002`... and appear in alerts, statistics and notifications like built-in ones. At most 50.

Through the API: `POST /api/rules/custom`, `PUT`/`DELETE /api/rules/custom/{id}`. The definition (`params`) is, for example:

```json
{"when": {"all": [{"field": "event_type", "op": "eq", "value": "authentication_failure"},
                  {"field": "username", "op": "in", "value": ["root", "admin"]}]},
 "threshold": 5, "window_minutes": 10, "group_by": "source_ip"}
```

### Sigma rules

*Import a Sigma rule* (or `POST /api/rules/sigma`) converts a Sigma YAML rule. Supported: searches over fields with the modifiers `contains`, `startswith`, `endswith`, `all` and `cidr`; keyword lists; conditions with `and`, `or`, `not`, parentheses and `1 of` / `all of` (`them` or a name pattern). Fields Horizon Events normalises (user names, addresses, host, service, message) are matched on those; other Windows field names (and `EventID`) are matched against the event's original fields. **Not supported, and refused with a reason:** `|re`, encodings (`|base64`, `|windash`...), `| count` and other aggregation, `near`. The `level` becomes the severity. Wildcards work only on the normalised fields.

### Testing a rule on the past

*Test this rule* (in the editor) and *Tune and test* (for built-in rules) answer "what would this have flagged over the last 1 to 90 days?" with the settings on screen, **without saving anything or sending notifications** (`POST /api/rules/replay`). The whole period is evaluated as one batch, so live alerts can be split a little differently, but the same activity is flagged. Up to 50,000 events (the newest) are examined.

## Sign-in locations (HZ-018, HZ-019)

These rules need a location database in MaxMind's format (for example the free GeoLite2 City, which requires a free account with MaxMind; Horizon Events cannot bundle it). Set its path in **Settings > Sign-in locations** or with `HORIZON_GEOIP_DB`. Lookups happen in that file on this computer; no address is sent anywhere. Private and reserved addresses are never located. Without a database the two rules stay silent, and alerts simply show no location. Country-level data cannot place a VPN user correctly, so treat these alerts as questions to ask, not findings.

## MITRE ATT&CK mapping

Each rule is tagged with ATT&CK techniques (shown as badges on alerts, on the Analytics coverage panel and in reports). The mapping is fixed in `backend/app/mitre.py`. It gives investigation context, not proof that a technique was used. Dashed badges mark low-confidence mappings.

| Rule | Techniques |
| --- | --- |
| HZ-001 Repeated login failures | T1110 Brute Force, T1110.001 Password Guessing |
| HZ-002 Unusual login hours | T1078 Valid Accounts |
| HZ-003 Unknown users | T1110 Brute Force, T1087 Account Discovery (low confidence) |
| HZ-004 Privilege escalation events | T1548.003 Sudo and Sudo Caching, T1098 Account Manipulation |
| HZ-005 Service failures | T1489 Service Stop (low confidence) |
| HZ-006 Account lockouts | T1110 Brute Force |
| HZ-007 Anomalous IP activity | T1110.003 Password Spraying, T1110 Brute Force |

Technique IDs and tactics follow ATT&CK Enterprise; re-check them against the current ATT&CK release before relying on them.
