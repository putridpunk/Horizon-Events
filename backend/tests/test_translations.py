"""The Portuguese interface texts must keep up with what the server sends: every recommended step and rule name
is shown through the dictionary in frontend/src/i18n/pt.js, so a new or reworded one without a translation
would silently stay English."""
import json
from pathlib import Path

from app.detection.registry import DEFAULT_RULES
from app.mitigation.advice import ADVICE

PT = (Path(__file__).resolve().parents[2] / "frontend" / "src" / "i18n" / "pt.js").read_text(encoding="utf-8")


def has_key(text: str) -> bool:
    return json.dumps(text, ensure_ascii=False) + ":" in PT


def test_every_recommended_step_is_translated():
    missing = [line for lines in ADVICE.values() for line in lines if not has_key(line)]
    assert missing == []


def test_every_rule_name_is_translated():
    assert [r["name"] for r in DEFAULT_RULES if not has_key(r["name"])] == []


def test_every_rule_description_is_translated():
    assert [r["description"] for r in DEFAULT_RULES if not has_key(r["description"])] == []
