"""Draw the MoeSOC application icon (original artwork, generated from geometry).

    python scripts/make_icon.py

Writes assets/icons/MoeSOC.ico (16, 20, 24, 32, 40, 48, 64, 128, 256 px) and
assets/icons/MoeSOC-256.png. The design: a dark rounded tile, a shield outlined in
the app's accent blue, and a white "detection pulse" across it. Every size is drawn
separately at 8x and downsampled, with heavier strokes at small sizes so the mark
stays legible in the taskbar and Explorer.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets" / "icons"
SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)
SCALE = 8

TILE_TOP = (27, 35, 52)  # #1B2334
TILE_BOTTOM = (14, 18, 27)  # #0E121B
ACCENT = (76, 141, 255)  # #4C8DFF, the app's accent
ACCENT_FILL = (26, 44, 84)  # #1A2C54, deep blue inside the shield
PULSE = (255, 255, 255)


def _bezier(p0, p1, p2, steps=32):
    return [
        (
            (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t**2 * p2[0],
            (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t**2 * p2[1],
        )
        for t in (i / steps for i in range(1, steps + 1))
    ]


def _shield(cx: float, top: float, width: float, height: float) -> list[tuple[float, float]]:
    """Heater shield: flat top with rounded shoulders, straight sides, curved to a point."""
    half = width / 2
    shoulder = width * 0.10
    side_end = top + height * 0.42
    bottom = (cx, top + height)
    right = [
        (cx + half - shoulder, top),
        *_bezier((cx + half - shoulder, top), (cx + half, top), (cx + half, top + shoulder), 8),
        (cx + half, side_end),
        *_bezier((cx + half, side_end), (cx + half, top + height * 0.80), bottom),
    ]
    left = [(2 * cx - x, y) for x, y in reversed(right[:-1])]
    return right + left


def draw(size: int) -> Image.Image:
    s = size * SCALE
    image = Image.new("RGBA", (s, s), (0, 0, 0, 0))

    # Tile with a vertical gradient, drawn into a rounded-rectangle mask.
    gradient = Image.new("RGBA", (s, s))
    g = ImageDraw.Draw(gradient)
    for y in range(s):
        t = y / (s - 1)
        color = tuple(round(a + (b - a) * t) for a, b in zip(TILE_TOP, TILE_BOTTOM, strict=True))
        g.line([(0, y), (s, y)], fill=(*color, 255))
    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, s - 1, s - 1], radius=round(s * 0.22), fill=255)
    image.paste(gradient, (0, 0), mask)
    d = ImageDraw.Draw(image, "RGBA")

    if size <= 20:
        # Tiny: a solid shield with a dark pulse cut through it reads best.
        shield = _shield(cx=s / 2, top=s * 0.13, width=s * 0.74, height=s * 0.76)
        d.polygon(shield, fill=ACCENT)
        y0 = s * 0.44
        pulse = [(s * 0.22, y0), (s * 0.40, y0), (s * 0.50, s * 0.24), (s * 0.60, s * 0.62),
                 (s * 0.68, y0), (s * 0.78, y0)]  # fmt: skip
        width = round(s * 0.11)
        color: tuple[int, ...] = TILE_BOTTOM
    else:
        small = size <= 32
        shield = _shield(
            cx=s / 2, top=s * 0.15, width=s * (0.66 if small else 0.60), height=s * 0.72
        )
        outline = round(s * (0.075 if small else 0.05))
        d.polygon(shield, fill=ACCENT_FILL, outline=ACCENT, width=outline)
        y0 = s * 0.45
        if small:
            pulse = [(s * 0.27, y0), (s * 0.41, y0), (s * 0.50, s * 0.28), (s * 0.59, s * 0.62),
                     (s * 0.66, y0), (s * 0.73, y0)]  # fmt: skip
            width = round(s * 0.075)
        else:
            pulse = [(s * 0.29, y0), (s * 0.40, y0), (s * 0.46, s * 0.33), (s * 0.54, s * 0.60),
                     (s * 0.60, s * 0.40), (s * 0.64, y0), (s * 0.71, y0)]  # fmt: skip
            width = round(s * 0.045)
        color = PULSE
    d.line(pulse, fill=color, width=width, joint="curve")
    radius = width / 2
    for x, y in (pulse[0], pulse[-1]):  # round line caps
        d.ellipse([x - radius, y - radius, x + radius, y + radius], fill=color)
    return image.resize((size, size), Image.Resampling.LANCZOS)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    images = [draw(size) for size in SIZES]
    largest = images[-1]
    largest.save(OUT / "MoeSOC-256.png")
    largest.save(OUT / "MoeSOC.ico", sizes=[(n, n) for n in SIZES], append_images=images[:-1])
    print(f"Wrote {OUT / 'MoeSOC.ico'} ({', '.join(map(str, SIZES))} px) and MoeSOC-256.png")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
