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

Windows event IDs recognised: 4624 (success), 4625 (failure; sub-status `0xC0000064` means unknown user), 4740 (lockout), 4672/4728/4732/4756 (privilege), 7031/7034 (service failure).

An alert means *suspicious activity worth investigating*, not a confirmed breach.
