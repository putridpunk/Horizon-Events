# MITRE ATT&CK Mapping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Tag detection rules and their alerts with ATT&CK techniques and tactics, and surface them in the API, dashboard and reports.

**Architecture:** A pure `app/mitre.py` table and helpers; API serialisers, statistics and reports consume it; the frontend renders badges and a coverage panel.

**Tech Stack:** existing Python/FastAPI/React stack; no new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-23-mitre-attack-design.md`

## Global Constraints

- Mapping: HZ-001 T1110, T1110.001; HZ-002 T1078; HZ-003 T1110, T1087 (low); HZ-004 T1548.003, T1098; HZ-005 T1489 (low); HZ-006 T1110; HZ-007 T1110.003, T1110.
- Tactics: T1110/T1110.001/T1110.003 Credential Access; T1078 Initial Access, Persistence, Privilege Escalation, Defense Evasion; T1087 Discovery; T1548.003 Privilege Escalation, Defense Evasion; T1098 Persistence, Privilege Escalation; T1489 Impact.
- Names: Brute Force, Password Guessing, Password Spraying, Valid Accounts, Account Discovery, Sudo and Sudo Caching, Account Manipulation, Service Stop.
- URL form: `https://attack.mitre.org/techniques/T1110/` and `https://attack.mitre.org/techniques/T1110/003/`.
- `mitre.py` imports no framework. Run tests with `.venv/Scripts/python.exe -m pytest` from `backend/`.

## Review Focus

- A rule id with no mapping (future rules) yields an empty list, not an error.
- Empty database: coverage endpoint returns every tactic with zero alerts, no crash.
- A technique shared by several rules counts each alert once, not per rule.
- Report HTML escapes technique names.

---

### Task 1: ATT&CK table and helpers

**Files:**
- Create: `backend/app/mitre.py`, `backend/tests/test_mitre.py`

**Interfaces:**
- Produces: `techniques_for_rule(rule_id: str) -> list[dict]` (keys `id, name, tactics, url, confidence`); `all_techniques() -> list[dict]` (keys `id, name, tactics, url`); `tactic_coverage(alerts_by_rule: dict[str, int]) -> list[dict]` (keys `tactic, techniques, alerts`; all tactics present in the table, fixed kill-chain order); `technique_counts(alerts_by_rule) -> list[dict]` (keys `id, name, tactics, url, alerts`).

- [ ] **Step 1: Write failing tests**: `test_every_registered_rule_has_valid_technique` (iterate `RULE_CLASSES`; non-empty; each id matches `^T\d{4}(\.\d{3})?$`), `test_urls` (T1110 and T1110.003 exact URLs), `test_unknown_rule_returns_empty`, `test_confidence_values` (HZ-005 and HZ-003's T1087 are `low`, HZ-001 `high`), `test_shared_technique_counts_each_alert_once` (`{"HZ-001": 2, "HZ-006": 3}` → T1110 alerts 5; HZ-001 maps T1110 once even though it has two techniques), `test_tactic_coverage_empty` (all tactics, zero alerts, includes "Credential Access" and "Impact").
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** the table (tactics tuple order: Initial Access, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Impact) and helpers. A tactic's `alerts` counts each rule's alerts once per tactic even when several of its techniques share the tactic; `techniques` is the number of distinct techniques mapped under it.
- [ ] **Step 4: Run** the full suite → PASS.
- [ ] **Step 5: Commit** `feat: MITRE ATT&CK mapping table`.

### Task 2: API and report integration

**Files:**
- Create: `backend/app/api/mitre.py`
- Modify: `backend/app/api/schemas.py` (`alert_out`, `rule_out` add `techniques`), `backend/app/api/statistics.py` (`GET /api/statistics/mitre`), `backend/app/services/statistics.py` (`alerts_by_rule(session) -> dict[str, int]`), `backend/app/reports/generator.py` (`techniques` in report, CSV rows `technique`, HTML section), `backend/app/main.py` (router), `backend/tests/test_api.py`, `backend/tests/test_statistics.py`

**Interfaces:**
- Consumes: Task 1 helpers.
- Produces: `GET /api/mitre/techniques` → `all_techniques()`; `GET /api/statistics/mitre` → `{tactics: tactic_coverage(...), techniques: technique_counts(...)}`; alert and rule JSON include `techniques` (from `techniques_for_rule`); report dict key `techniques` = `technique_counts` for alerts in the period.

- [ ] **Step 1: Write failing tests**: `test_alert_includes_techniques` (import linux auth; HZ-001 alert has technique id `T1110`), `test_rules_include_techniques`, `test_mitre_techniques_endpoint`, `test_statistics_mitre_empty_db` (all tactics, zero alerts), `test_statistics_mitre_after_import` (Credential Access alerts ≥ 1), `test_report_includes_techniques` (JSON key, CSV section `technique`, HTML contains "ATT&amp;CK" and escapes a `<script>` technique name when monkeypatched).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** the full suite → PASS.
- [ ] **Step 5: Commit** `feat: ATT&CK in API and reports`.

### Task 3: Dashboard, docs and executable rebuild

**Files:**
- Create: `frontend/src/components/TechniqueBadges.jsx`, `frontend/src/components/MitrePanel.jsx`
- Modify: `frontend/src/services/api.js` (`getMitreStats`), `frontend/src/components/AlertDrawer.jsx` (badges), `frontend/src/pages/Alerts.jsx` (compact badges in the rule column), `frontend/src/pages/Analytics.jsx` (panel), `frontend/src/pages/Reports.jsx` (techniques list), `frontend/src/theme.css`, `README.md`, `docs/detection-rules.md`, `docs/api.md`

**Interfaces:**
- `TechniqueBadges({techniques})` renders `<a class="badge technique">` per technique (`id`, title = name and tactics, link to url, `low` confidence dimmed); `MitrePanel({stats})` shows tactic bars and a technique table.

- [ ] **Step 1: Implement** components, wiring and docs (mapping table and a note that techniques follow ATT&CK Enterprise and should be re-checked against the current release).
- [ ] **Step 2: Verify build**: `npm run build` passes.
- [ ] **Step 3: Rebuild and run the exe** with a temp `LOCALAPPDATA`; confirm `/api/statistics/mitre` shows Credential Access alerts and the Alerts and Analytics pages show badges and the panel (browser pane), no console errors; run the full pytest suite.
- [ ] **Step 4: Commit** `feat: ATT&CK badges, coverage panel and docs`.
