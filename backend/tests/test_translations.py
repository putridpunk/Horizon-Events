"""The Portuguese interface texts must keep up with what the server sends: every recommended step and rule name
is shown through the language files in frontend/src/i18n/langs/, so a new or reworded one without a translation
would silently stay English."""
import json
from pathlib import Path

import pytest

from app.detection.registry import DEFAULT_RULES
from app.mitigation.advice import ADVICE

LANGS = sorted((Path(__file__).resolve().parents[2] / "frontend" / "src" / "i18n" / "langs").glob("*.js"))
TEXTS = {path.stem: path.read_text(encoding="utf-8") for path in LANGS}


def has_key(text: str, language_file: str) -> bool:
    return json.dumps(text, ensure_ascii=False) + ":" in language_file


def test_there_are_files_for_every_supported_language():
    assert sorted(TEXTS) == sorted("pt fr es de it pl ru el zh ja ko ar".split())


@pytest.mark.parametrize("code", sorted(TEXTS))
def test_every_recommended_step_is_translated(code):
    missing = [line for lines in ADVICE.values() for line in lines if not has_key(line, TEXTS[code])]
    assert missing == []


@pytest.mark.parametrize("code", sorted(TEXTS))
def test_every_rule_name_and_description_is_translated(code):
    missing = [t for r in DEFAULT_RULES for t in (r["name"], r["description"]) if not has_key(t, TEXTS[code])]
    assert missing == []
