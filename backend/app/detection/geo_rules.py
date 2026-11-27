"""Rules that need to know where an address is (a location database the user provides, see app/geo). With no database
configured they find nothing."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from app.detection.rules import Rule
from app.domain import Detection, EventType, Severity
from app.geo.locator import get_locator, haversine_km

SIGN_INS = [EventType.authentication_success, EventType.remote_login]


class NewCountryLogin(Rule):
    id = "HZ-018"
    name = "Sign-in from a new country"
    description = "An account signed in from a country it has not signed in from recently."
    severity = Severity.medium
    event_types = SIGN_INS
    default_params = {"lookback_days": 90, "min_history": 1, "ignore_countries": []}

    def evaluate(self, new_events, history) -> list[Detection]:
        locator = get_locator()
        if locator is None:
            return []
        ignore = {c.upper() for c in self.params["ignore_countries"]}
        by_user: dict[str, list] = defaultdict(list)
        for e in new_events:
            if e.event_type in self.event_types and e.username and e.source_ip:
                by_user[e.username].append(e)
        found: dict[tuple[str, str], list] = {}
        for user, events in by_user.items():
            lo = min(e.timestamp for e in events) - timedelta(days=self.params["lookback_days"])
            seen = history.events_in_window(self.event_types, lo, max(e.timestamp for e in events), username=user)
            placed = [(p.timestamp, p.id, (locator.lookup(p.source_ip) or None)) for p in seen]
            for e in sorted(events, key=lambda x: x.timestamp):
                place = locator.lookup(e.source_ip)
                if place is None or not place.country_code or place.country_code.upper() in ignore:
                    continue
                before = [loc for ts, pid, loc in placed if ts < e.timestamp and pid != e.id and loc and loc.country_code]
                if len(before) < self.params["min_history"] or any(l.country_code == place.country_code for l in before):
                    continue
                found.setdefault((user, place.country_code), []).append((e, place))
        out = []
        for (user, _), items in found.items():
            events = [e for e, _ in items]
            place = items[0][1]
            out.append(self._detection(
                events, ip=events[0].source_ip, user=user,
                description=f"{user} signed in from {place.label()}, a country this account has not signed in from "
                            f"in the last {self.params['lookback_days']} days."))
        return out


class ImpossibleTravel(Rule):
    id = "HZ-019"
    name = "Impossible travel"
    description = "An account signed in from two places too far apart to have travelled between them in the time."
    severity = Severity.high
    event_types = SIGN_INS
    default_params = {"window_hours": 24, "max_speed_kmh": 900, "min_distance_km": 500, "country_change_hours": 1}

    def _impossible(self, a, place_a, b, place_b) -> tuple[bool, float | None]:
        hours = (b.timestamp - a.timestamp).total_seconds() / 3600
        if hours <= 0:
            return False, None
        if place_a.has_coordinates and place_b.has_coordinates:
            km = haversine_km(place_a, place_b)
            return km >= self.params["min_distance_km"] and km / hours > self.params["max_speed_kmh"], km
        different = bool(place_a.country_code and place_b.country_code and place_a.country_code != place_b.country_code)
        return different and hours < self.params["country_change_hours"], None

    def evaluate(self, new_events, history) -> list[Detection]:
        locator = get_locator()
        if locator is None:
            return []
        window = timedelta(hours=self.params["window_hours"])
        by_user: dict[str, list] = defaultdict(list)
        for e in new_events:
            if e.event_type in self.event_types and e.username and e.source_ip:
                by_user[e.username].append(e)
        out: list[Detection] = []
        for user, events in by_user.items():
            seen = history.events_in_window(self.event_types, min(e.timestamp for e in events) - window,
                                            max(e.timestamp for e in events), username=user)
            placed = [(p, loc) for p in seen if (loc := locator.lookup(p.source_ip)) is not None]
            reported: set[tuple] = set()
            for e in sorted(events, key=lambda x: x.timestamp):
                place = locator.lookup(e.source_ip)
                if place is None:
                    continue
                for p, p_place in sorted(placed, key=lambda t: t[0].timestamp, reverse=True):
                    if p.id == e.id or not 0 < (e.timestamp - p.timestamp).total_seconds() <= window.total_seconds():
                        continue
                    bad, km = self._impossible(p, p_place, e, place)
                    if not bad or (p.source_ip, e.source_ip) in reported:
                        continue
                    reported.add((p.source_ip, e.source_ip))
                    minutes = int((e.timestamp - p.timestamp).total_seconds() // 60)
                    apart = f", {km:,.0f} km apart" if km is not None else ""
                    out.append(self._detection(
                        [p, e], ip=e.source_ip, user=user, window=int(window.total_seconds() // 60),
                        description=f"{user} signed in from {p_place.label()} ({p.source_ip}) and {minutes} minutes later "
                                    f"from {place.label()} ({e.source_ip}){apart}."))
                    break
        return out
