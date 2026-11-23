"""HZ-007: ML-based anomaly detection over per-IP hourly activity windows."""
from __future__ import annotations

from datetime import timedelta

from app.detection.rules import Rule
from app.domain import SEVERITY_RANK, Detection, Event, EventType, Severity
from app.ml import model as ml
from app.ml.features import group_windows, window_features


class AnomalousIpActivity(Rule):
    id = "HZ-007"
    name = "Anomalous IP activity"
    description = "An IP address behaved unlike the learned baseline of normal activity."
    severity = Severity.medium
    event_types = list(EventType)
    default_params = {"min_events": 3}

    def evaluate(self, new_events: list[Event], history) -> list[Detection]:
        bundle = ml.load()
        if bundle is None:
            return []
        flagged: dict[str, list[tuple]] = {}  # ip -> [(score, start, window, reasons, severity)]
        for (ip, start) in group_windows(new_events):
            try:
                window = history.events_in_window(
                    self.event_types, start, start + timedelta(hours=1) - timedelta(microseconds=1), source_ip=ip)
                if len(window) < self.params["min_events"]:
                    continue
                vector = window_features(window)
                outlier, value = ml.score(bundle, vector)
                if not outlier:
                    continue
                reasons = "; ".join(ml.explain(bundle, vector))
            except Exception:  # a bad window must never break an import
                continue
            sev = Severity.high if ml.is_high(bundle, value) else self.severity
            flagged.setdefault(ip, []).append((value, start, window, reasons, sev))

        out: list[Detection] = []
        for ip, items in flagged.items():  # one detection per IP: a continuing pattern is one alert
            worst = min(items, key=lambda i: i[0])
            events = {e.id if e.id is not None else id(e): e for _, _, w, _, _ in items for e in w}
            hours = len(items)
            desc = (f"Unusual activity from {ip} in {hours} hourly window{'s' if hours > 1 else ''}, "
                    f"most recently around {max(i[1] for i in items):%Y-%m-%d %H:%M}."
                    + (f" Most unusual: {worst[3]}." if worst[3] else ""))
            severity = max((i[4] for i in items), key=lambda s: SEVERITY_RANK[s])
            out.append(self._detection(list(events.values()), severity=severity, ip=ip, window=60,
                                       description=desc))
        return out
