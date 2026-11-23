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

Windows event IDs recognised: 4624 (success), 4625 (failure; sub-status `0xC0000064` means unknown user), 4740 (lockout), 4672/4728/4732/4756 (privilege), 7031/7034 (service failure).

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
