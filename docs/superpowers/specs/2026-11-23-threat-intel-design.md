# Threat Intelligence Enrichment (Milestone 5, part 4) — Design

Date: 2026-11-23. Approved in conversation ("feeds, go ahead").

## Intent

Add reputation context to alerts without leaking log data: download public blocklists, check IPs locally, show "known malicious" with the feed names. Portfolio feature: privacy-preserving, explicit about network use, demonstrable offline.

## Goals / non-goals

- Goals: two real feeds (abuse.ch Feodo Tracker botnet C2 IPs; Spamhaus DROP netblocks) plus a clearly synthetic demo feed; local matching; enrichment on alerts and event detail; a refresh action that runs only on user click; feed status in the API and on Analytics; a count in reports.
- Non-goals: per-IP lookups to third-party services (possible later as opt-in), automatic or scheduled downloads, user-supplied feed URLs, changing detection or severity based on intel.
- Anti-goals: any IP from the logs leaving the machine; background network traffic; implying the demo feed is real intelligence.

## Approaches considered

- **Downloaded blocklists, matched locally (chosen):** no key, no IP leaves the machine.
- **Per-IP reputation API (e.g. AbuseIPDB):** needs a key and sends log IPs to a third party. Deferred.
- **Both at once:** more surface and more setup for the same portfolio value. Deferred.

## Design

- Feeds (fixed in code, https only, no user-supplied URLs): `feodo` = `https://feodotracker.abuse.ch/downloads/ipblocklist.txt` (one IP per line, `#` comments); `spamhaus_drop` = `https://www.spamhaus.org/drop/drop_v4.json` (JSON Lines, field `cidr`). Spamhaus asks for no more than one fetch per hour, so a feed is not refetched within 60 minutes (the refresh result says `too_soon`). Requests use a generic `User-Agent: HorizonEvents/0.1`, a 20 s timeout and a 10 MB size cap.
- `backend/app/intel/feeds.py` (pure): `FEEDS` table; `parse_feodo(text) -> list[str]`, `parse_spamhaus_drop(text) -> list[str]` (CIDR strings; invalid lines skipped); `checkable(ip) -> bool` (valid IP and not loopback, link-local, multicast, unspecified or RFC 1918/private ranges; documentation ranges are allowed so the demo works); `IpMatcher(entries: dict[feed_id, list[str]])` with `lookup(ip) -> list[str]`.
- Storage: new tables `intel_feeds` (feed id, name, source `network|demo`, fetched_at, entry count) and `intel_entries` (feed id, cidr). A refresh replaces a feed's entries atomically; a failed refresh keeps the old data.
- `backend/app/intel/service.py`: `refresh_feeds(session, feed_ids=None, fetch=http_fetch, now=utcnow) -> list[dict]` (per feed `status: updated|too_soon|error`, entries, message); `ensure_demo_feed(session)` loads a synthetic feed (`demo`, "Synthetic demo feed (not real intelligence)") covering `198.51.100.77`, `203.0.113.7` and `203.0.113.99`, only when no feeds are stored; `get_matcher(session)` (cached until feed data changes); `enrich(session, ip) -> {"listed": bool, "feeds": [{"id", "name"}]}`.
- API: `alert_out` and the event detail response gain `intel`; `GET /api/intel/status` (feeds, entries, fetched_at, source, `min_refresh_minutes`); `POST /api/intel/refresh` body `{"feeds": [...]}` (optional; 422 for unknown ids). The report gains `intel_matches` (alerts in the period whose IP is listed).
- Startup: `seed` and the launcher call `ensure_demo_feed`.
- Frontend: a "Known malicious" badge (feed names in its tooltip) on the alert list and drawer; a "Threat intelligence feeds" card on Analytics with last-refreshed times and a "Refresh feeds" button that states what it will contact.
- Security and privacy: matching is local; the only network action is the explicit refresh; feed URLs are constants (no SSRF); responses are size-capped and parsed defensively; no secrets involved.

## Testing

Parsers on well-formed and malformed input; matcher CIDR containment and IPv6 safety; `checkable` for private, loopback, documentation and invalid inputs; refresh with an injected fake fetcher (tests never touch the network): update, `too_soon` within an hour, error keeps old entries, oversize response rejected; demo feed loads once; API alert includes `intel` for a demo-listed IP and `listed: false` for others; refresh endpoint with a monkeypatched fetcher; unknown feed id 422; report count.

## Left to the builder

Badge colours and card layout, and the exact wording of refresh messages.
