"""MITRE ATT&CK context for detection rules. A fixed, offline table; no framework imports.

Technique IDs and tactics follow ATT&CK Enterprise. Re-check them against the current ATT&CK release
before relying on them for reporting.
"""
from __future__ import annotations

TACTICS = ("Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
           "Credential Access", "Discovery", "Impact")

# technique id -> (name, tactics)
TECHNIQUES: dict[str, tuple[str, tuple[str, ...]]] = {
    "T1110": ("Brute Force", ("Credential Access",)),
    "T1110.001": ("Password Guessing", ("Credential Access",)),
    "T1110.003": ("Password Spraying", ("Credential Access",)),
    "T1078": ("Valid Accounts", ("Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion")),
    "T1087": ("Account Discovery", ("Discovery",)),
    "T1548.003": ("Sudo and Sudo Caching", ("Privilege Escalation", "Defense Evasion")),
    "T1098": ("Account Manipulation", ("Persistence", "Privilege Escalation")),
    "T1489": ("Service Stop", ("Impact",)),
    "T1204.002": ("Malicious File", ("Execution",)),
}

# rule id -> [(technique id, confidence)]
RULE_TECHNIQUES: dict[str, list[tuple[str, str]]] = {
    "HZ-001": [("T1110", "high"), ("T1110.001", "high")],
    "HZ-002": [("T1078", "high")],
    "HZ-003": [("T1110", "high"), ("T1087", "low")],
    "HZ-004": [("T1548.003", "high"), ("T1098", "high")],
    "HZ-005": [("T1489", "low")],
    "HZ-006": [("T1110", "high")],
    "HZ-007": [("T1110.003", "high"), ("T1110", "high")],
    "HZ-008": [("T1204.002", "high")],
}


def technique_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def _technique(tid: str) -> dict:
    name, tactics = TECHNIQUES[tid]
    return {"id": tid, "name": name, "tactics": list(tactics), "url": technique_url(tid)}


def techniques_for_rule(rule_id: str) -> list[dict]:
    return [{**_technique(tid), "confidence": conf} for tid, conf in RULE_TECHNIQUES.get(rule_id, [])]


def all_techniques() -> list[dict]:
    return [_technique(tid) for tid in sorted(TECHNIQUES)]


def technique_counts(alerts_by_rule: dict[str, int]) -> list[dict]:
    """Alerts per technique; an alert counts once toward each technique its rule maps to."""
    out = []
    for tid in TECHNIQUES:
        n = sum(alerts_by_rule.get(rule, 0) for rule, maps in RULE_TECHNIQUES.items()
                if any(t == tid for t, _ in maps))
        out.append({**_technique(tid), "alerts": n})
    return sorted(out, key=lambda t: (-t["alerts"], t["id"]))


def tactic_coverage(alerts_by_rule: dict[str, int]) -> list[dict]:
    """Per tactic: number of mapped techniques and alerts (each rule's alerts counted once per tactic)."""
    out = []
    for tactic in TACTICS:
        techs = {tid for tid, (_, tactics) in TECHNIQUES.items() if tactic in tactics}
        rules = [r for r, maps in RULE_TECHNIQUES.items() if any(t in techs for t, _ in maps)]
        out.append({"tactic": tactic, "techniques": len(techs), "alerts": sum(alerts_by_rule.get(r, 0) for r in rules)})
    return out
