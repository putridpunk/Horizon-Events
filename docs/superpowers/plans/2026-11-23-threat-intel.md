# Threat Intelligence Enrichment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enrich alerts with local blocklist matches from downloadable feeds, refreshed only on user click.

**Architecture:** Pure parsers and matcher in `app/intel/feeds.py`; storage and refresh in `app/intel/service.py`; API fields and endpoints; a frontend badge and feed card.

**Tech Stack:** Python stdlib (`ipaddress`, `urllib`), existing FastAPI/SQLAlchemy/React; no new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-23-threat-intel-design.md`

## Global Constraints

- Feeds: `feodo` https://feodotracker.abuse.ch/downloads/ipblocklist.txt; `spamhaus_drop` https://www.spamhaus.org/drop/drop_v4.json (JSON Lines, key `cidr`). Min refresh interval 60 minutes per feed. Timeout 20 s, size cap 10 MB, User-Agent `HorizonEvents/0.1`.
- Tests never use the real network; use an injected fetcher.
- No IP from the logs is ever sent anywhere. The only network action is `POST /api/intel/refresh`.
- Do not download from the real feeds during verification without asking the user first.
- Run tests with `.venv/Scripts/python.exe -m pytest` from `backend/`.

## Review Focus

- Malformed feed lines (blank, comments, garbage, invalid CIDR, IPv6) are skipped, not fatal.
- A failed or oversized refresh keeps the previous entries.
- A second refresh within an hour does not hit the network (`too_soon`).
- Private, loopback and invalid IPs never match and never raise.
- Alerts with no `source_ip` return `listed: false`.

---

### Task 1: Feed parsers, checkable and matcher

**Files:**
- Create: `backend/app/intel/__init__.py`, `backend/app/intel/feeds.py`, `backend/tests/test_intel_feeds.py`

**Interfaces:**
- Produces: `FEEDS: dict[str, dict]` (`name, url, description`); `parse_feodo(text: str) -> list[str]`; `parse_spamhaus_drop(text: str) -> list[str]`; `PARSERS: dict[str, Callable]`; `checkable(ip: str | None) -> bool`; `IpMatcher(entries: dict[str, list[str]])` with `lookup(ip: str | None) -> list[str]` (feed ids, sorted).

- [ ] **Step 1: Write failing tests**: `test_parse_feodo_skips_comments_blanks_and_garbage`, `test_parse_feodo_normalises_single_ip_to_cidr` (`"1.2.3.4"` → `"1.2.3.4/32"`), `test_parse_spamhaus_drop_jsonl` (valid lines, a malformed line, a line without `cidr`, an IPv6 cidr kept or skipped consistently, documented in the test), `test_checkable` (public `8.8.8.8` and doc range `203.0.113.7` True; `10.0.0.1`, `192.168.1.15`, `127.0.0.1`, `169.254.1.1`, `""`, `None`, `"nonsense"` False), `test_matcher_cidr_containment_and_multiple_feeds`, `test_matcher_returns_empty_for_unchecked_ip`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: threat feed parsers and matcher`.

### Task 2: Storage, refresh, demo feed, enrichment

**Files:**
- Create: `backend/app/intel/service.py`, `backend/tests/test_intel_service.py`
- Modify: `backend/app/database/models.py` (`IntelFeedRow`, `IntelEntryRow`)

**Interfaces:**
- Consumes: Task 1.
- Produces: `http_fetch(url: str, timeout: int = 20, max_bytes: int = 10_485_760) -> str` (raises `ValueError` on oversize); `refresh_feeds(session, feed_ids: list[str] | None = None, fetch=http_fetch, now=utcnow) -> list[dict]` (keys `feed, status, entries, message`; status `updated|too_soon|error`); `ensure_demo_feed(session) -> bool`; `feed_status(session) -> list[dict]` (`id, name, source, fetched_at, entries, description`); `enrich(session, ip: str | None) -> dict` (`listed: bool, feeds: [{id, name}]`).

- [ ] **Step 1: Write failing tests** (fake fetcher): `test_refresh_updates_feed_and_replaces_entries`, `test_second_refresh_within_hour_is_too_soon` (fetcher not called), `test_refresh_after_an_hour_allowed` (inject `now`), `test_failed_refresh_keeps_old_entries`, `test_oversize_response_rejected` (real `http_fetch` against a monkeypatched `urlopen` returning too many bytes raises), `test_demo_feed_loaded_once`, `test_enrich_demo_ip_listed_and_private_not`, `test_enrich_none_ip`, `test_unknown_feed_id_raises_valueerror`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** (matcher cached per process keyed by the tuple of `(feed id, fetched_at)`; refresh commits per feed). **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: threat intel storage and refresh`.

### Task 3: API, reports and startup hooks

**Files:**
- Create: `backend/app/api/intel.py`, `backend/tests/test_intel_api.py`
- Modify: `backend/app/api/alerts.py` and `backend/app/api/events.py` (add `intel`), `backend/app/api/schemas.py` if helpful, `backend/app/reports/generator.py` (`intel_matches`), `backend/app/main.py` (router), `backend/app/seed.py` and `backend/run_app.py` (`ensure_demo_feed`)

**Interfaces:**
- `GET /api/intel/status` → `{feeds: feed_status(...), min_refresh_minutes: 60}`; `POST /api/intel/refresh` body `{"feeds": [..]}` optional → `{results: [...], feeds: [...]}`, 422 on unknown id. Alert list and detail items and the event detail gain `intel`.

- [ ] **Step 1: Write failing tests**: `test_alert_includes_intel_for_demo_ip` (ensure demo feed, import `slow_spray.log`, alert for `198.51.100.77` has `intel.listed` true with feed name containing "Synthetic"), `test_alert_without_listed_ip_not_listed`, `test_event_detail_includes_intel`, `test_status_endpoint`, `test_refresh_endpoint_with_fake_fetch` (monkeypatch `app.intel.service.http_fetch` via the API's fetcher argument), `test_refresh_unknown_feed_422`, `test_report_counts_intel_matches`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** the full suite → PASS.
- [ ] **Step 5: Commit** `feat: threat intel API, reports and startup`.

### Task 4: Dashboard, docs, executable check

**Files:**
- Create: `frontend/src/components/IntelBadge.jsx`, `frontend/src/components/IntelCard.jsx`
- Modify: `frontend/src/services/api.js`, `frontend/src/pages/Alerts.jsx`, `frontend/src/components/AlertDrawer.jsx`, `frontend/src/pages/Analytics.jsx`, `frontend/src/theme.css`, `README.md`, `docs/architecture.md`, `docs/api.md`, `docs/detection-rules.md` (no change unless needed)

**Interfaces:**
- `IntelBadge({intel})` renders a red "Known malicious" badge with feed names as title when `intel.listed`. `IntelCard` lists feeds (name, source, entries, last refreshed) with a "Refresh feeds" button and per-feed result messages; the text states that the button contacts abuse.ch and spamhaus.org and that no log data is sent.

- [ ] **Step 1: Implement** components, wiring and docs (privacy statement, feeds and licence/limits note: Feodo CC0, Spamhaus DROP free with at most hourly fetches and its terms of use).
- [ ] **Step 2: Verify build**: `npm run build` passes.
- [ ] **Step 3: Rebuild and run the exe** (`HORIZON_SEED` default): alerts for `198.51.100.77`, `203.0.113.7` show the badge; the Analytics card lists the synthetic feed; the refresh button must not be clicked against the real feeds without asking the user first. Run the full suite.
- [ ] **Step 4: Commit** `feat: threat intel badges, feed card and docs`.
