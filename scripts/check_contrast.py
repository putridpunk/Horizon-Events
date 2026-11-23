"""WCAG contrast check for the text and background pairs the UI uses, in both themes.

Reads the design tokens from frontend/src/theme.css. Run `python scripts/check_contrast.py` for a table;
it exits with status 1 if any pair is below 4.5:1 (WCAG AA for normal text). The same check runs as a test.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

CSS = Path(__file__).resolve().parents[1] / "frontend" / "src" / "theme.css"
MIN_RATIO = 4.5

# (foreground token, background token): every combination the stylesheet actually puts on screen.
PAIRS = [
    ("text", "bg"), ("text", "surface"), ("text", "surface-2"), ("text", "hover"),
    ("muted", "bg"), ("muted", "surface"), ("muted", "surface-2"), ("muted", "hover"),
    ("accent", "surface"), ("accent", "bg"), ("accent", "accent-soft"), ("accent", "hover"),
    ("on-accent", "accent"), ("on-accent", "accent-hover"),
    ("critical", "critical-bg"), ("high", "high-bg"), ("medium", "medium-bg"), ("low", "low-bg"), ("ok", "ok-bg"),
    ("critical", "surface"), ("high", "surface"), ("ok", "surface"), ("medium", "surface"), ("low", "surface"),
    ("sidebar-text", "sidebar"), ("sidebar-muted", "sidebar"), ("#ffffff", "sidebar"), ("#ffffff", "sidebar-active"),
    ("sidebar-text", "sidebar-active"),
]


def parse_blocks(css: str) -> dict[str, dict[str, str]]:
    """{'light': {token: '#rrggbb'}, 'dark': {...}} from the two theme blocks."""
    blocks = {}
    for name, header in (("light", r':root,\s*:root\[data-theme="light"\]\s*\{'), ("dark", r':root\[data-theme="dark"\]\s*\{')):
        match = re.search(header + r"(.*?)\n\}", css, re.S)
        if not match:
            raise ValueError(f"theme block {name!r} not found in {CSS}")
        blocks[name] = {k: v.lower() for k, v in re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})\b", match.group(1))}
    return blocks


def luminance(hex_color: str) -> float:
    channels = [int(hex_color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast(a: str, b: str) -> float:
    la, lb = luminance(a), luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def evaluate() -> list[tuple[str, str, str, float]]:
    """[(theme, foreground, background, ratio)] for every pair in both themes."""
    blocks = parse_blocks(CSS.read_text(encoding="utf-8"))
    rows = []
    for theme, tokens in blocks.items():
        for fg, bg in PAIRS:
            f = fg if fg.startswith("#") else tokens[fg]
            rows.append((theme, fg, bg, contrast(f, tokens[bg])))
    return rows


def main() -> int:
    rows = evaluate()
    worst = 99.0
    for theme, fg, bg, ratio in rows:
        flag = "" if ratio >= MIN_RATIO else "   <-- below 4.5"
        worst = min(worst, ratio)
        print(f"{theme:5} {fg:14} on {bg:14} {ratio:5.2f}{flag}")
    failing = [r for r in rows if r[3] < MIN_RATIO]
    print(f"\n{len(rows)} pairs checked, lowest ratio {worst:.2f}, {len(failing)} below {MIN_RATIO}")
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
