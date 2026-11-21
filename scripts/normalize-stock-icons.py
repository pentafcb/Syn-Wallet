#!/usr/bin/env python3
"""Normalize stock logos into uniform app tiles.

The raw FMP haul (assets-src/stock-logos/) is a mixed bag: glyphs on
transparency, baked white/black squares, wide wordmarks, sizes from
100px to 1534px. Clipping those into round discs (the old treatment)
cropped wordmarks and mixed white boxes with floating glyphs — it read
as buggy. This script bakes every logo into ONE tile system instead:

  - output: 200x200 PNG, logo never cropped, never stretched
  - opaque logos (their own baked background) fill the tile as-is
  - transparent logos are trimmed to their content, scaled to fit a
    148px box (74% of the tile, consistent padding), and composited on
    a flat tile tone: light neutral #EEF0F3 for dark glyphs, charcoal
    #1A1F28 for light glyphs (white wordmarks — Invesco, Zoom, IBM —
    are invisible on a light tile; the tone follows the logo, the
    geometry never changes)

The client then just fills a rounded-square tile with the image
(object-fit: cover on an already-square, already-composited asset =
exact fill, zero crop). Run: python3 scripts/normalize-stock-icons.py
Then regenerate client/lib/stock-icons.ts from public/assets/s.
"""
import os, sys
import numpy as np
from PIL import Image

SRC = os.path.join(os.path.dirname(__file__), '..', 'assets-src', 'stock-logos')
DST = os.path.join(os.path.dirname(__file__), '..', 'public', 'assets', 's')
TILE = 200
FIT = 148  # logo content box inside the tile (74%)
LIGHT = (238, 240, 243, 255)
DARK = (26, 31, 40, 255)

def normalize(path: str) -> Image.Image:
    im = Image.open(path).convert('RGBA')
    a = np.asarray(im)[:, :, 3]
    transparent_frac = float((a < 250).mean())
    if transparent_frac <= 0.02:
        # Opaque: the logo carries its own background — fill the tile.
        return im.resize((TILE, TILE), Image.LANCZOS)
    # Transparent (or mostly): trim to content, judge glyph tone.
    bbox = Image.fromarray(a).getbbox()
    content = im.crop(bbox) if bbox else im
    px = np.asarray(content).astype(np.float32)
    solid = px[:, :, 3] > 128
    if solid.sum() == 0:
        tone = LIGHT
    else:
        rgb = px[:, :, :3][solid]
        lum = 0.299 * rgb[:, 0] + 0.587 * rgb[:, 1] + 0.114 * rgb[:, 2]
        tone = DARK if (lum.mean() > 185 and float((lum < 110).mean()) < 0.18) else LIGHT
    tile = Image.new('RGBA', (TILE, TILE), tone)
    c = content.copy()
    c.thumbnail((FIT, FIT), Image.LANCZOS)
    tile.alpha_composite(c, ((TILE - c.width) // 2, (TILE - c.height) // 2))
    return tile

def main() -> int:
    os.makedirs(DST, exist_ok=True)
    files = sorted(f for f in os.listdir(SRC) if f.endswith('.png'))
    for f in files:
        out = normalize(os.path.join(SRC, f))
        out.save(os.path.join(DST, f), optimize=True)
    print(f'normalized {len(files)} stock logos -> {DST}')
    return 0

if __name__ == '__main__':
    sys.exit(main())
