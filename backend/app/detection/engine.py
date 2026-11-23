"""Rule-based detection engine. Independent of the web layer and the database."""
from __future__ import annotations

from app.detection.registry import build_rule
from app.detection.rules import EventHistory, Rule
from app.domain import Detection, Event


class DetectionEngine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    @classmethod
    def from_definitions(cls, definitions: list[dict]) -> "DetectionEngine":
        """Build from stored rule definitions, keeping only enabled, known rules."""
        rules = [build_rule(d) for d in definitions if d.get("enabled", True)]
        return cls([r for r in rules if r is not None])

    def run(self, new_events: list[Event], history: EventHistory) -> list[Detection]:
        detections: list[Detection] = []
        for rule in self.rules:
            detections.extend(rule.evaluate(new_events, history))
        return detections
