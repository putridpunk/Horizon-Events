"""Regenerate assets/horizon.ico: a square navy tile with a white H. Needs Pillow (requirements-build.txt)."""
from pathlib import Path

from PIL import Image, ImageDraw

NAVY, WHITE, ACCENT = (20, 33, 61, 255), (255, 255, 255, 255), (91, 156, 245, 255)
SIZES = [16, 24, 32, 48, 64, 128, 256]


def draw(size: int) -> Image.Image:
    s = size * 4  # draw large, then downsample for smooth edges
    img = Image.new("RGBA", (s, s), NAVY)
    d = ImageDraw.Draw(img)
    margin, bar = int(s * 0.24), int(s * 0.14)
    top, bottom = margin, s - margin
    d.rectangle([margin, top, margin + bar, bottom], fill=WHITE)
    d.rectangle([s - margin - bar, top, s - margin, bottom], fill=WHITE)
    mid = s // 2
    d.rectangle([margin, mid - bar // 2, s - margin, mid + bar // 2], fill=ACCENT)
    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    out = Path(__file__).resolve().parents[1] / "assets" / "horizon.ico"
    out.parent.mkdir(exist_ok=True)
    draw(256).save(out, format="ICO", sizes=[(n, n) for n in SIZES])
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
