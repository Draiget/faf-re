"""Writes the streak texture of the waterfall curtain (src/moho/terrain/water/Waterfall.cpp, docs/projects/RIVERS.md).

    python make_streak.py [output.dds]

A 64 x 256 white texture whose alpha is a pattern of vertical streaks of different length and strength, soft at the
left and right edges (the ribbon of a beam fades out there) and tileable from top to bottom, so a beam that repeats it
along its length and scrolls it shows water running down. DXT5, no mip maps. Deterministic: the same bytes every time.
Needs Pillow.
"""
import math
import os
import random
import sys

from PIL import Image

W, H = 64, 256
DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "fafengine", "textures", "particles", "waterfall_streak_01.dds")


def smooth(t):
    return t * t * (3.0 - 2.0 * t)


def noise_grid(rng, nx, ny):
    return [[rng.random() for _ in range(nx)] for _ in range(ny)]


def sample(grid, u, v):
    """Smooth periodic value noise: u in [0, nx) wraps too, v in [0, ny) wraps."""
    ny = len(grid)
    nx = len(grid[0])
    x0 = int(math.floor(u)) % nx
    y0 = int(math.floor(v)) % ny
    x1 = (x0 + 1) % nx
    y1 = (y0 + 1) % ny
    fx = smooth(u - math.floor(u))
    fy = smooth(v - math.floor(v))
    a = grid[y0][x0] * (1 - fx) + grid[y0][x1] * fx
    b = grid[y1][x0] * (1 - fx) + grid[y1][x1] * fx
    return a * (1 - fy) + b * fy


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    rng = random.Random(20261112)
    # Streaks are long along the image's y and narrow along x: few cells along y, many across.
    coarse = noise_grid(rng, 20, 5)
    fine = noise_grid(rng, 40, 10)
    im = Image.new("RGBA", (W, H))
    px = im.load()
    for y in range(H):
        for x in range(W):
            n = 0.65 * sample(coarse, x / W * 20.0, y / H * 5.0) + 0.35 * sample(fine, x / W * 40.0, y / H * 10.0)
            # contrast: mostly streaks with gaps, never fully clear (water is a sheet with streaks in it)
            a = min(max((n - 0.32) * 3.2, 0.0), 1.0)
            a = 0.28 + 0.72 * a
            # soft edges, so the ribbons blend where they overlap
            e = min(x, W - 1 - x) / 10.0
            a *= smooth(min(e, 1.0))
            # a little blue in the shadows of the streaks
            shade = 0.85 + 0.15 * a
            px[x, y] = (int(255 * shade), int(255 * min(shade + 0.04, 1.0)), 255, int(round(a * 255)))
    im.save(out, pixel_format="DXT5")
    print("wrote", out, os.path.getsize(out), "bytes")


if __name__ == "__main__":
    main()
