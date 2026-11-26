"""Measures the light a frame of an in-game light test added around given points.

    python probe.py <on-frame.bmp> <quiet-frame.bmp>[,<quiet-frame.bmp>...] name:x:y[:r] ...

The quiet frames show the same scene without the light (several are averaged: clouds move over the ground, which would show up as noise in
a single one). For each probe the script prints, within a disk of radius r pixels (default 70) around (x, y) of the full-size frame:

    peak L    the strongest pixel: L = on / quiet - 1 per channel, the light the shader added (ground colour cancels out)
    hue       the peak scaled so its largest channel is 1: the colour of the light source
    mean L    the average over the disk, which is steadier than a single pixel

For a point light directly above flat ground the expected peak is  L = c / (1 + c)  with  c = colour x intensity x a x (0.35 + 0.65 a)  and
a = 1 - (h / radius)^2 for a light at height h (the shader's falloff, docs/DYNAMIC_LIGHTS.md); the disk mean is about 0.8 of that.
"""
import sys

from PIL import Image


def main():
    on = Image.open(sys.argv[1]).convert('RGB')
    quiet = [Image.open(p).convert('RGB') for p in sys.argv[2].split(',')]
    w, h = on.size

    def light(x, y):
        a = on.getpixel((x, y))
        b = [sum(q.getpixel((x, y))[c] for q in quiet) / float(len(quiet)) for c in range(3)]
        return [max(0.0, a[c] / max(b[c], 8.0) - 1.0) for c in range(3)]

    for spec in sys.argv[3:]:
        parts = spec.split(':')
        name, cx, cy = parts[0], int(parts[1]), int(parts[2])
        r = int(parts[3]) if len(parts) > 3 else 70
        best = None
        acc = [0.0, 0.0, 0.0]
        n = 0
        for y in range(cy - r, cy + r, 3):
            for x in range(cx - r, cx + r, 3):
                if (x - cx) ** 2 + (y - cy) ** 2 > r * r or not (0 <= x < w and 0 <= y < h):
                    continue
                v = light(x, y)
                n += 1
                for c in range(3):
                    acc[c] += v[c]
                if best is None or sum(v) > best[0]:
                    best = (sum(v), v, x, y)
        if n == 0:
            print('%-10s outside the frame' % name)
            continue
        mean = [a / n for a in acc]
        top = max(best[1]) or 1.0
        mtop = max(mean) or 1.0
        print('%-10s peak (%4d,%4d) L (%.3f %.3f %.3f) hue (%.2f %.2f %.2f) | mean L (%.3f %.3f %.3f) hue (%.2f %.2f %.2f)' % (
            name, best[2], best[3], best[1][0], best[1][1], best[1][2], best[1][0] / top, best[1][1] / top, best[1][2] / top,
            mean[0], mean[1], mean[2], mean[0] / mtop, mean[1] / mtop, mean[2] / mtop))


if __name__ == '__main__':
    main()
