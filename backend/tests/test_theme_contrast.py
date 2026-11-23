"""Guards readability: every text and background colour pair the UI uses must meet WCAG AA (4.5:1) in both
themes. If this fails after a colour change, adjust the token in frontend/src/theme.css."""
import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_contrast.py"
spec = importlib.util.spec_from_file_location("check_contrast", SCRIPT)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

ROWS = check.evaluate()


@pytest.mark.parametrize("theme,fg,bg,ratio", ROWS, ids=[f"{t}:{f}-on-{b}" for t, f, b, _ in ROWS])
def test_pair_meets_wcag_aa(theme, fg, bg, ratio):
    assert ratio >= check.MIN_RATIO, f"{fg} on {bg} in the {theme} theme is {ratio:.2f}:1 (needs {check.MIN_RATIO}:1)"


def test_both_themes_define_the_same_tokens():
    blocks = check.parse_blocks(check.CSS.read_text(encoding="utf-8"))
    assert set(blocks["light"]) == set(blocks["dark"])


def test_known_values_of_the_ratio_function():
    assert check.contrast("#000000", "#ffffff") == pytest.approx(21.0)
    assert check.contrast("#ffffff", "#ffffff") == pytest.approx(1.0)
    assert check.contrast("#777777", "#ffffff") == pytest.approx(4.48, abs=0.01)  # a classic just-failing grey


def test_no_hard_coded_colours_outside_the_token_blocks():
    css = check.CSS.read_text(encoding="utf-8")
    after_tokens = css[css.index("/* ---------- application shell"):]
    # #fff on the dark sidebar and white-on-accent are intentional; nothing else should bypass the tokens
    stray = [c for c in __import__("re").findall(r"#[0-9a-fA-F]{3,8}\b", after_tokens) if c.lower() not in {"#fff", "#ffffff"}]
    assert stray == []
