#!/usr/bin/env python3
"""Render the extension's PNG icons (a shield with a check-less hook) with Pillow.

Run:  .venv/bin/python extension/tools/make_icons.py
Deterministic; draws at 8x and downsamples for clean edges.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parents[1] / "icons"
SIZES = (16, 32, 48, 128)
SCALE = 8
BLUE = (36, 85, 214, 255)
WHITE = (255, 255, 255, 255)


def render(size: int) -> Image.Image:
    s = size * SCALE
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    m = s * 0.08
    top, bottom = m, s - m
    left, right = m + s * 0.04, s - m - s * 0.04
    mid = s / 2
    # shield outline
    pts = [(left, top + s * 0.08), (mid, top), (right, top + s * 0.08), (right, s * 0.52),
           (mid + s * 0.22, s * 0.78), (mid, bottom), (mid - s * 0.22, s * 0.78), (left, s * 0.52)]
    d.polygon(pts, fill=BLUE)
    # hook / fish-hook glyph: a white "U" with a small eye dot, nodding to "phish"
    w = max(2, int(s * 0.075))
    cx, cy, r = mid, s * 0.46, s * 0.17
    d.arc([cx - r, cy - r * 0.2, cx + r, cy + r * 1.8], 0, 180, fill=WHITE, width=w)
    d.line([cx + r, cy + r * 0.8, cx + r, cy - r * 0.9], fill=WHITE, width=w)
    d.ellipse([cx - r - w * 0.2, cy - r * 0.35, cx - r + w * 1.4, cy + r * 0.2], fill=WHITE)
    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for size in SIZES:
        render(size).save(OUT / f"icon{size}.png", optimize=True)
        print(f"icons/icon{size}.png")


if __name__ == "__main__":
    main()
