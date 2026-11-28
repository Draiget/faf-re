#!/usr/bin/env python3
"""Reads the captures of the water recorder (console: ren_WaterRec <count>, ren_WaterRecEvery <frames>; files rec_NNNNN.bin in
FAF_WATERREC_DIR, default C:/ProgramData/FAForever/logs/waterrec) and turns them into things that can be read without a screenshot.

  waterrec.py stats   <dir>                       one line per capture: time, weight, hulls, sources, height and foam extremes
  waterrec.py sheet   <dir> [-o out.png] [--n 12] [--range 0.25] [--scale 2]
                                                  contact sheet: height (blue below the sea, orange above), foam (white), land (grey),
                                                  hulls (green box and heading), sources (dots: cyan pull, yellow push)
  waterrec.py profile <dir> [--back 4 8 16 32] [--index N]
                                                  across the track of the first hull, at distances behind it: height and foam by lateral offset,
                                                  the peaks, and the angle they make with the track (a V has a steady angle)
  waterrec.py headings <dir>                      does the recorded heading of the first hull point the way it moved between captures? (1 = yes)
  waterrec.py along   <dir> [--index N]           height and foam along the track of the first hull, from 20 ahead to 60 behind, at lateral offsets

Format (little endian): u32 magic 'WRC1', crop, hulls, sources; f32 cell, originX, originZ (world, of crop cell 0 0), time, tick, gameSpeed,
sourceWeight, steps, dt, centreX, centreZ, waterLevel; hulls (8 f32: x z hx hz speed halfLength halfBeam radius); sources (8 f32: x z radius push foam
a b c); height f32[crop*crop]; foam f32[crop*crop]; land u8[crop*crop]. Rows are z, columns are x.
"""
import argparse
import glob
import math
import os
import struct
import sys
from array import array

try:
    from PIL import Image, ImageDraw
except ImportError:  # the text commands work without it
    Image = None


def load(folder):
    records = []
    for path in sorted(glob.glob(os.path.join(folder, 'rec_*.bin'))):
        with open(path, 'rb') as f:
            data = f.read()
        magic, crop, nh, ns = struct.unpack_from('<4I', data, 0)
        if magic != 0x31435257:
            continue
        info = struct.unpack_from('<12f', data, 16)
        pos = 16 + 48
        hulls = [struct.unpack_from('<8f', data, pos + 32 * i) for i in range(nh)]
        pos += 32 * nh
        sources = [struct.unpack_from('<8f', data, pos + 32 * i) for i in range(ns)]
        pos += 32 * ns
        cells = crop * crop
        height = array('f')
        height.frombytes(data[pos:pos + 4 * cells])
        pos += 4 * cells
        foam = array('f')
        foam.frombytes(data[pos:pos + 4 * cells])
        pos += 4 * cells
        land = data[pos:pos + cells]
        records.append(dict(path=path, crop=crop, cell=info[0], ox=info[1], oz=info[2], time=info[3], tick=info[4], speed=info[5], weight=info[6],
                            steps=info[7], dt=info[8], cx=info[9], cz=info[10], level=info[11], hulls=hulls, sources=sources, height=height, foam=foam,
                            land=land))
    return records


def sample(rec, field, x, z):
    """Bilinear read of a field at a world position; None outside the crop or on land."""
    n = rec['crop']
    fx = (x - rec['ox']) / rec['cell'] - 0.5
    fz = (z - rec['oz']) / rec['cell'] - 0.5
    ix, iz = int(math.floor(fx)), int(math.floor(fz))
    if ix < 0 or iz < 0 or ix + 1 >= n or iz + 1 >= n:
        return None
    ax, az = fx - ix, fz - iz
    f = rec[field]
    v00, v10, v01, v11 = f[iz * n + ix], f[iz * n + ix + 1], f[(iz + 1) * n + ix], f[(iz + 1) * n + ix + 1]
    return (v00 * (1 - ax) + v10 * ax) * (1 - az) + (v01 * (1 - ax) + v11 * ax) * az


def cmd_stats(recs):
    print('idx  tick   time  weight steps hulls src   h min   h max  mean|h|  foam max  foam>0.5')
    for i, r in enumerate(recs):
        h, fo = r['height'], r['foam']
        mean = sum(abs(v) for v in h) / len(h)
        print('%3d %6d %6.2f %6.2f %5d %5d %4d  %7.3f %7.3f %8.4f %9.2f %8d' % (i, r['tick'], r['time'], r['weight'], r['steps'], len(r['hulls']), len(r['sources']),
              min(h), max(h), mean, max(fo), sum(1 for v in fo if v > 0.5)))


def colour(h, fo, land, rng):
    if land:
        return (70, 70, 70)
    t = max(-1.0, min(1.0, h / rng))
    if t >= 0:
        base = (int(40 + 215 * t), int(60 + 100 * t), int(90 - 60 * t))
    else:
        base = (int(40 + 20 * t), int(60 + 60 * t), int(90 - 110 * t)) if t > -1 else (20, 30, 190)
    a = max(0.0, min(1.0, fo))
    return tuple(int(base[k] * (1 - a) + 255 * a) for k in range(3))


def render(rec, rng, scale):
    n = rec['crop']
    im = Image.new('RGB', (n, n))
    px = im.load()
    h, fo, land = rec['height'], rec['foam'], rec['land']
    for j in range(n):
        for i in range(n):
            k = j * n + i
            px[i, j] = colour(h[k], fo[k], land[k], rng)
    im = im.resize((n * scale, n * scale), Image.NEAREST)
    d = ImageDraw.Draw(im)

    def to_px(x, z):
        return ((x - rec['ox']) / rec['cell']) * scale, ((z - rec['oz']) / rec['cell']) * scale

    for (x, z, radius, push, foam, a, b, c) in rec['sources']:
        sx, sz = to_px(x, z)
        r = max(1.0, radius / rec['cell'] * scale * 0.25)
        d.ellipse([sx - r, sz - r, sx + r, sz + r], outline=(255, 230, 0) if push >= 0 else (0, 255, 255))
    for (x, z, hx, hz, speed, hl, hb, radius) in rec['hulls']:
        px_, pz_ = -hz, hx
        pts = [(x + hx * hl * sa + px_ * hb * sb, z + hz * hl * sa + pz_ * hb * sb) for sa, sb in ((1, 1), (1, -1), (-1, -1), (-1, 1))]
        pts = [to_px(*p) for p in pts]
        d.line(pts + [pts[0]], fill=(0, 255, 0), width=1)
        a = to_px(x, z)
        b = to_px(x + hx * hl * 1.5, z + hz * hl * 1.5)
        d.line([a, b], fill=(255, 0, 255), width=1)
    d.text((4, 2), 't=%.2fs tick %d w=%.2f' % (rec['time'], rec['tick'], rec['weight']), fill=(255, 255, 255))
    return im


def cmd_sheet(recs, out, count, rng, scale):
    if Image is None:
        sys.exit('Pillow is needed for sheets')
    withHull = [r for r in recs if r['hulls'] and r['hulls'][0][4] > 0.5]
    pool = withHull if len(withHull) >= count else recs
    step = max(1, len(pool) // count)
    chosen = pool[::step][:count]
    tiles = [render(r, rng, scale) for r in chosen]
    cols = 3 if len(tiles) > 4 else 2
    rows = (len(tiles) + cols - 1) // cols
    w, h = tiles[0].size
    sheet = Image.new('RGB', (cols * w, rows * h))
    for i, t in enumerate(tiles):
        sheet.paste(t, ((i % cols) * w, (i // cols) * h))
    sheet.save(out)
    print('wrote', out, len(tiles), 'tiles, height scale +-%.2f' % rng)


def first_hull(recs, index):
    for r in recs[index:]:
        if r['hulls'] and r['hulls'][0][4] > 0.5:
            return r, r['hulls'][0]
    return None, None


def cmd_profile(recs, backs, index):
    rec, hull = first_hull(recs, index)
    if rec is None:
        sys.exit('no hull under way in the captures')
    x, z, hx, hz, speed, hl, hb, radius = hull
    px, pz = -hz, hx
    print('capture %s: hull at (%.1f %.1f) heading (%.2f %.2f) speed %.1f, half length %.1f, half beam %.1f' % (os.path.basename(rec['path']), x, z, hx, hz, speed, hl, hb))
    for back in backs:
        row = []
        peaks = []
        prev = None
        for k in range(-40, 41):
            lateral = k * 0.5 * 1.0
            hh = sample(rec, 'height', x - hx * back + px * lateral, z - hz * back + pz * lateral)
            ff = sample(rec, 'foam', x - hx * back + px * lateral, z - hz * back + pz * lateral)
            row.append((lateral, hh, ff))
        # local extrema of |height| and foam above thresholds
        for i in range(1, len(row) - 1):
            l, hh, ff = row[i]
            if hh is None or row[i - 1][1] is None or row[i + 1][1] is None:
                continue
            if abs(hh) > 0.03 and abs(hh) >= abs(row[i - 1][1]) and abs(hh) >= abs(row[i + 1][1]):
                peaks.append((l, hh, ff))
        print('\n%4.0f behind the centre: lateral -20..+20 (height bar, F = foam > 0.4)' % back)
        line = ''
        for l, hh, ff in row:
            if hh is None:
                line += '?'
            elif ff is not None and ff > 0.4:
                line += 'F'
            else:
                line += '+' if hh > 0.03 else ('-' if hh < -0.03 else '.')
        print('  ' + line)
        for l, hh, ff in peaks[:8]:
            ang = math.degrees(math.atan2(abs(l), max(back - 0.0, 0.1)))
            print('   peak at lateral %+5.1f: height %+.3f foam %.2f  angle %.0f deg' % (l, hh, ff if ff is not None else -1, ang))


def cmd_headings(recs):
    agree = total = 0
    for a, b in zip(recs, recs[1:]):
        if not a['hulls'] or not b['hulls']:
            continue
        x0, z0, hx, hz = a['hulls'][0][:4]
        x1, z1 = b['hulls'][0][:2]
        moved = (x1 - x0) * hx + (z1 - z0) * hz
        if abs(x1 - x0) + abs(z1 - z0) < 0.05 or abs(x1 - x0) + abs(z1 - z0) > 5:
            continue
        total += 1
        agree += 1 if moved > 0 else 0
    print('heading agrees with the movement in %d of %d capture pairs' % (agree, total))


def cmd_along(recs, index):
    rec, hull = first_hull(recs, index)
    if rec is None:
        sys.exit('no hull under way in the captures')
    x, z, hx, hz, speed, hl, hb, radius = hull
    px, pz = -hz, hx
    print('hull speed %.1f half length %.1f half beam %.1f; along the track from 20 ahead (+) to 60 behind (-); heights x100 / foam x10' % (speed, hl, hb))
    for lateral in (0.0, hb, 2 * hb, 4 * hb):
        hs, fs = [], []
        for d in range(20, -61, -4):
            hh = sample(rec, 'height', x + hx * d + px * lateral, z + hz * d + pz * lateral)
            ff = sample(rec, 'foam', x + hx * d + px * lateral, z + hz * d + pz * lateral)
            hs.append('  ?' if hh is None else '%+4d' % round(hh * 100))
            fs.append(' ?' if ff is None else '%2d' % min(99, round(ff * 10)))
        print('lateral %5.1f height ' % lateral + ' '.join(hs))
        print('              foam   ' + ' '.join(fs))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('cmd', choices=['stats', 'sheet', 'profile', 'along', 'headings'])
    ap.add_argument('dir')
    ap.add_argument('-o', default='waterrec_sheet.png')
    ap.add_argument('--n', type=int, default=12)
    ap.add_argument('--range', type=float, default=0.25)
    ap.add_argument('--scale', type=int, default=2)
    ap.add_argument('--back', type=float, nargs='*', default=[4, 8, 16, 32])
    ap.add_argument('--index', type=int, default=0)
    args = ap.parse_args()
    recs = load(args.dir)
    if not recs:
        sys.exit('no captures in ' + args.dir)
    if args.cmd == 'stats':
        cmd_stats(recs)
    elif args.cmd == 'sheet':
        cmd_sheet(recs, args.o, args.n, args.range, args.scale)
    elif args.cmd == 'headings':
        cmd_headings(recs)
    elif args.cmd == 'profile':
        cmd_profile(recs, args.back, args.index)
    else:
        cmd_along(recs, args.index)


if __name__ == '__main__':
    main()
