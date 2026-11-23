import re

from app.detection.registry import RULE_CLASSES
from app.mitre import TACTICS, tactic_coverage, technique_counts, techniques_for_rule


def test_every_registered_rule_has_valid_technique():
    for rule_id in RULE_CLASSES:
        techs = techniques_for_rule(rule_id)
        assert techs, rule_id
        assert all(re.fullmatch(r"T\d{4}(\.\d{3})?", t["id"]) and t["tactics"] for t in techs)


def test_urls():
    by_id = {t["id"]: t for t in techniques_for_rule("HZ-007")}
    assert by_id["T1110"]["url"] == "https://attack.mitre.org/techniques/T1110/"
    assert by_id["T1110.003"]["url"] == "https://attack.mitre.org/techniques/T1110/003/"


def test_unknown_rule_returns_empty():
    assert techniques_for_rule("HZ-999") == []


def test_confidence_values():
    assert techniques_for_rule("HZ-005")[0]["confidence"] == "low"
    assert {t["id"]: t["confidence"] for t in techniques_for_rule("HZ-003")}["T1087"] == "low"
    assert all(t["confidence"] == "high" for t in techniques_for_rule("HZ-001"))


def test_shared_technique_counts_each_alert_once():
    counts = {t["id"]: t["alerts"] for t in technique_counts({"HZ-001": 2, "HZ-006": 3})}
    assert counts["T1110"] == 5 and counts["T1110.001"] == 2 and counts["T1489"] == 0


def test_tactic_coverage_empty():
    cov = tactic_coverage({})
    assert [c["tactic"] for c in cov] == list(TACTICS)
    assert all(c["alerts"] == 0 for c in cov) and {"Credential Access", "Impact"} <= {c["tactic"] for c in cov}


def test_tactic_counts_rule_once_per_tactic():
    cov = {c["tactic"]: c["alerts"] for c in tactic_coverage({"HZ-001": 4, "HZ-004": 1})}
    assert cov["Credential Access"] == 4 and cov["Privilege Escalation"] == 1
