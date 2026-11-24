# Alert mitigation: plan

Spec: `docs/superpowers/specs/2026-11-24-mitigation-design.md`

1. `backend/app/mitigation/`: `advice.py` (text per rule), `firewall.py` (rule names, params, checks), `elevate.py`
   (ShellExecuteEx runas + wait), `quarantine.py` (move/restore with guards), `service.py` (settings, proposals,
   approve/dismiss/undo, history, auto-quarantine hook). `database/mitigation_models.py`.
2. `api/mitigation.py`; wire in `main.py` (`HORIZON_MITIGATION=1`), `ScanService` hook, `run_app.py` (env + quarantine dir).
3. Frontend: `MitigationPanel` in the alert drawer, `pages/Mitigation.jsx` (settings, history), route, api, mocks, tests.
4. Docs, full suites, real-file check of quarantine and `netsh show rule` quoting, rebuild exe, commit.
