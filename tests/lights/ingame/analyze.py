"""Compares a frame of an in-game light test with the same frame of a lights-off control run and reports where the lights added colour.

    python analyze.py <on-dir> <off-dir> <frame name> [min-delta] [out.png]

Both folders hold the back-buffer dumps of the same scripted scene (FAF_GAL_DUMP_DIR); the scene is static, so the only difference between
two frames is the light. For every pixel the lit terrain is dest * (1 + L) with L the light the shader added, so

    L = on / off - 1                     per channel

is the light itself, independent of the colour of the ground: its hue is the hue of the light source, its size the strength. A blob is a
connected area where the sum of L over the channels is above `min-delta`. For each blob the script prints the centre (in pixels of the
frame), the size, the peak L per channel and the hue (peak L scaled so its largest channel is 1).

The numbers it prints are compared by hand with the DYNLIGHT-TEST lines of the log (colour and strength of every light that was created).
Needs Pillow only.
"""
import sys

from PIL import Image


def load(path, scale):
    im = Image.open(path).convert('RGB')
    w, h = im.size
    return im.resize((w // scale, h // scale), Image.BOX)


def best_off_frame(on_dir, off_dir, frame):
    """The frame of the control run that looks most like `frame` (the runs are not in step: loading takes a different time): the one with the
    smallest mean absolute difference at a coarse scale. The lights change little of the picture, so the right frame wins clearly."""
    import glob
    import os
    ref = load('%s/%s' % (on_dir, frame), 16).convert('RGB').tobytes()
    best, best_d = None, None
    for path in sorted(glob.glob(os.path.join(off_dir, 'd3d12_*.bmp'))):
        cand = load(path, 16).convert('RGB').tobytes()
        d = sum(abs(a - b) for a, b in zip(ref, cand)) / float(len(ref))
        if best_d is None or d < best_d:
            best, best_d = os.path.basename(path), d
    return best, best_d


def main():
    on_dir, off_dir, frame = sys.argv[1], sys.argv[2], sys.argv[3]
    off_frame, mean_diff = best_off_frame(on_dir, off_dir, frame)
    print('control frame for %s: %s (mean difference %.2f of 255)' % (frame, off_frame, mean_diff))
    min_delta = float(sys.argv[4]) if len(sys.argv) > 4 else 0.12
    out_png = sys.argv[5] if len(sys.argv) > 5 else None
    scale = 4
    on = load('%s/%s' % (on_dir, frame), scale)
    off = load('%s/%s' % (off_dir, off_frame), scale)
    w, h = on.size
    pon, poff = on.load(), off.load()

    # L = on / off - 1 per channel; the HUD and units are identical in both frames, so they cancel (L = 0)
    light = [[(0.0, 0.0, 0.0)] * w for _ in range(h)]
    total = [[0.0] * w for _ in range(h)]
    for y in range(h):
        for x in range(w):
            a, b = pon[x, y], poff[x, y]
            v = tuple(max(0.0, a[c] / max(b[c], 8.0) - 1.0) if b[c] >= 8 else 0.0 for c in range(3))
            light[y][x] = v
            total[y][x] = v[0] + v[1] + v[2]

    # A light that covers the whole view (the explosion flash of the commander arriving) adds an almost constant L everywhere: it is the
    # background, and what is looked for are the lights on top of it. Take the per-channel median away.
    med = []
    for c in range(3):
        values = sorted(light[y][x][c] for y in range(0, h, 2) for x in range(0, w, 2))
        med.append(values[len(values) // 2])
    print('background light (median L per channel): (%.3f %.3f %.3f)' % tuple(med))
    for y in range(h):
        for x in range(w):
            v = tuple(max(0.0, light[y][x][c] - med[c]) for c in range(3))
            light[y][x] = v
            total[y][x] = v[0] + v[1] + v[2]

    seen = [[False] * w for _ in range(h)]
    blobs = []
    for y in range(h):
        for x in range(w):
            if seen[y][x] or total[y][x] < min_delta:
                continue
            stack = [(x, y)]
            seen[y][x] = True
            pixels = []
            while stack:
                cx, cy = stack.pop()
                pixels.append((cx, cy))
                for nx, ny in ((cx + 1, cy), (cx - 1, cy), (cx, cy + 1), (cx, cy - 1)):
                    if 0 <= nx < w and 0 <= ny < h and not seen[ny][nx] and total[ny][nx] >= min_delta:
                        seen[ny][nx] = True
                        stack.append((nx, ny))
            if len(pixels) >= 6:
                blobs.append(pixels)

    blobs.sort(key=lambda p: -len(p))
    print('frame %s: %d blobs (min delta %.2f, scale 1/%d)' % (frame, len(blobs), min_delta, scale))
    for i, pixels in enumerate(blobs[:16]):
        cx = sum(p[0] for p in pixels) / len(pixels) * scale
        cy = sum(p[1] for p in pixels) / len(pixels) * scale
        peak = [max(light[y][x][c] for x, y in pixels) for c in range(3)]
        top = max(peak) or 1.0
        hue = [p / top for p in peak]
        # the pixel with the largest total L: its channel ratios are the least mixed with the blob edge
        bx, by = max(pixels, key=lambda p: total[p[1]][p[0]])
        centre = light[by][bx]
        ctop = max(centre) or 1.0
        print('  blob %d: centre (%d, %d) px, %d px, peak L (%.3f %.3f %.3f), hue (%.2f %.2f %.2f), at the peak L (%.3f %.3f %.3f) hue (%.2f %.2f %.2f)' % (
            i, cx, cy, len(pixels) * scale * scale, peak[0], peak[1], peak[2], hue[0], hue[1], hue[2],
            centre[0], centre[1], centre[2], centre[0] / ctop, centre[1] / ctop, centre[2] / ctop))

    if out_png:
        img = Image.new('RGB', (w, h))
        px = img.load()
        for y in range(h):
            for x in range(w):
                v = light[y][x]
                px[x, y] = tuple(min(255, int(c * 400)) for c in v)
        img.resize((w * 2, h * 2)).save(out_png)
        print('wrote', out_png)


if __name__ == '__main__':
    main()
