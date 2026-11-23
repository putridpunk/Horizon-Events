# MITRE ATT&CK Mapping (Milestone 5, part 2) — Design

Date: 2026-11-23. Approved in conversation ("fixed, go ahead").

## Intent

Give analysts context: show which ATT&CK techniques and tactics each detection rule relates to, on alerts, on the Analytics page and in reports. Portfolio feature: accurate, offline, small.

## Goals / non-goals

- Goals: a fixed, built-in rule-to-technique table; techniques on alerts and rules in the API; tactic coverage and technique counts on Analytics; a techniques section in reports; badges linking to attack.mitre.org.
- Non-goals: editable mappings, per-event mapping, live fetching of the ATT&CK dataset, new dependencies.
- Anti-goal: implying certainty. An alert is suspicious activity, and the mapping is context, so weak fits are marked `low` confidence.

## Approaches considered

- **Fixed table in code (chosen):** offline, testable, no storage.
- **Table in the database, editable:** needs UI and migrations for little value. Rejected by the user.
- **Download the ATT&CK STIX dataset:** heavy, needs network. Rejected.

## Design

- `backend/app/mitre.py` (pure Python, no framework imports): `TECHNIQUES` (id, name, tactics, url) and `RULE_TECHNIQUES: dict[rule_id, list[(technique_id, confidence)]]`. Functions: `techniques_for_rule(rule_id) -> list[dict]` (`id, name, tactics, url, confidence`), `all_techniques() -> list[dict]`, `tactic_coverage(alerts_by_rule: dict[str, int]) -> list[dict]` (`tactic, techniques, alerts`), `technique_counts(alerts_by_rule) -> list[dict]` (`id, name, tactics, url, alerts`). An alert counts once toward each technique and tactic its rule maps to.
- Mapping (confidence in brackets): HZ-001 T1110, T1110.001; HZ-002 T1078; HZ-003 T1110, T1087 (low); HZ-004 T1548.003, T1098; HZ-005 T1489 (low); HZ-006 T1110; HZ-007 T1110.003, T1110.
- URLs: `https://attack.mitre.org/techniques/T1110/` and sub-techniques `https://attack.mitre.org/techniques/T1110/003/`.
- API: `alert_out` and `rule_out` gain `techniques`; `GET /api/mitre/techniques`; `GET /api/statistics/mitre` returns `{tactics, techniques}`; the report gains `techniques` (JSON, CSV and HTML).
- Frontend: technique badges in the alert drawer and alert list; an "ATT&CK coverage" panel on Analytics (tactic bars and technique table).
- Docs: README and `docs/detection-rules.md` list the mapping, with a note that techniques follow ATT&CK Enterprise and should be re-checked against the current release.

## Testing

Every rule in the registry has at least one valid technique; IDs match `T\d{4}(\.\d{3})?`; URL building for sub-techniques; coverage counts on seeded data; API responses include techniques; report sections present and HTML-escaped.

## Left to the builder

Badge styling and the exact layout of the coverage panel.
