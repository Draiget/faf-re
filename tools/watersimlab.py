#!/usr/bin/env python3
"""Driver and measurements of the headless water lab (tools/watersimlab, docs/WATER_SIMULATION.md "Water lab").

  watersimlab.py run      [--terrain coast] [--seconds 40] [--from 20] [--every 4] [--out DIR] [--src FILE]
                          runs the real simulation shader of the game on the CPU (no game, no GPU) and writes captures + look images
  watersimlab.py metrics  DIR      numbers of the last captures: crest alignment with the shore, foam on the shore, limits
  watersimlab.py selftest [--terrain coast]
                          runs a lab simulation and checks the numbers against what a sea should look like, then the `gate` case (exit 1 when one fails)
  watersimlab.py gate     where the simulation takes a source on a mock map with water bodies (a raised lake, a dry polder, a basin below the sea, no sea):
                          pure CPU, no GPU (WaterSourceGate.h, what SimAddSource and the feeds ask)
  watersimlab.py domains  the simulation per water of a map with water bodies, 9 groups of checks (parity with the single level, two basins and a wall,
                          touching waters, a dry polder, the contour of each water's own level, the fetch of small lakes, the shore fields against a brute-force
                          reference, the window centre, the source gate against the shader): the real shader on WARP over synthetic maps, exit 1 when one fails;
                          WATERSIMLAB_ONLY=fetch,brute,centre,parity,basins,dry,beach,gate runs a part
  watersimlab.py strip    DIR [-o out.png] [--crop x0,y0,x1,y1]   the look images of a run, side by side
  watersimlab.py impact   [--size 6] [--impacts 1] [--gap 0.25] [--seconds 8] [--legacy] [--capillary 100] [--damping 100] [--out DIR]
                          open sea, impacts at the middle: runs the lab and prints the numbers of the splash (ringing of the middle, volume, energy,
                          front speed, roughness of the rings, foam); --check exits 1 when a number is out of its range
  watersimlab.py wake     [--speed 5] [--length 2.9] [--beam 0.6] [--radius 3.4] [--scale 2] [--seconds 40] [--out DIR]
                          open sea, one hull sails through the middle: the wave height and the foam across the track at distances behind it

The captures are the format of the in-game recorder (tools/waterrec.py reads them too).
"""
import argparse
import math
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import waterrec  # noqa: E402

EXE = os.environ.get('WATERSIMLAB_EXE') or os.path.join(HERE, 'watersimlab', 'watersimlab.exe')
SRC = os.environ.get('WATERSIMLAB_SRC') or os.path.join(HERE, '..', 'src', 'moho', 'terrain', 'water', 'WaterSimulation.cpp')
# captures and images go to WATERSIMLAB_OUT (default: a folder in the temp directory), never into the repository
LAB_ROOT = os.environ.get('WATERSIMLAB_OUT') or os.path.join(tempfile.gettempdir(), 'watersimlab')
OUT = os.path.join(LAB_ROOT, 'lab')


def run(terrain='coast', seconds=40.0, start=20.0, every=4.0, out=OUT, src=SRC, look=3, extra=()):
    if not os.path.exists(EXE):
        sys.exit('build the lab first: tools/watersimlab/build.ps1')
    cmd = [EXE, '--src', src, '--out', out, '--terrain', terrain, '--seconds', str(seconds), '--from', str(start), '--every', str(every), '--look', str(look)]
    cmd += list(extra)
    subprocess.run(cmd, check=True)
    return out


def distance_to_land(land, n):
    """Chamfer distance (cells) to the nearest land cell: two passes, 3-4 weights."""
    inf = 1e9
    d = [0.0 if land[i] else inf for i in range(n * n)]
    for j in range(n):
        for i in range(n):
            k = j * n + i
            v = d[k]
            if i > 0: v = min(v, d[k - 1] + 1.0)
            if j > 0:
                v = min(v, d[k - n] + 1.0)
                if i > 0: v = min(v, d[k - n - 1] + 1.4142)
                if i < n - 1: v = min(v, d[k - n + 1] + 1.4142)
            d[k] = v
    for j in range(n - 1, -1, -1):
        for i in range(n - 1, -1, -1):
            k = j * n + i
            v = d[k]
            if i < n - 1: v = min(v, d[k + 1] + 1.0)
            if j < n - 1:
                v = min(v, d[k + n] + 1.0)
                if i < n - 1: v = min(v, d[k + n + 1] + 1.4142)
                if i > 0: v = min(v, d[k + n - 1] + 1.4142)
            d[k] = v
    return d


def smooth(field, n, radius):
    """Box blur (both directions) of a float list."""
    for axis in (0, 1):
        out = [0.0] * (n * n)
        for j in range(n):
            for i in range(n):
                s = 0.0
                c = 0
                for o in range(-radius, radius + 1):
                    ii = i + o if axis == 0 else i
                    jj = j + o if axis == 1 else j
                    if 0 <= ii < n and 0 <= jj < n:
                        s += field[jj * n + ii]
                        c += 1
                out[j * n + i] = s / c
        field = out
    return field


def measure(rec):
    n = rec['crop']
    cell = rec['cell']
    land = rec['land']
    h = rec['height']
    foam = rec['foam']
    dist = smooth(distance_to_land(land, n), n, 3)          # cells, smoothed: the shore normal is its gradient
    hs = smooth([h[i] for i in range(n * n)], n, 1)
    # alignment of the crests with the shore: the gradient of the height against the gradient of the distance
    sum_c = sum_s = weight = 0.0
    band = 0
    for j in range(4, n - 4):
        for i in range(4, n - 4):
            k = j * n + i
            d = dist[k] * cell
            if land[k] or d < 8.0 or d > 60.0:
                continue
            gx = hs[k + 1] - hs[k - 1]
            gz = hs[k + n] - hs[k - n]
            hx = dist[k + 1] - dist[k - 1]
            hz = dist[k + n] - dist[k - n]
            gm = math.hypot(gx, gz)
            hm = math.hypot(hx, hz)
            if gm < 1e-4 or hm < 1e-3:
                continue
            # angle between the crest normal and the shore normal, doubled (a crest normal has no sign)
            cosd = (gx * hx + gz * hz) / (gm * hm)
            sind = (gx * hz - gz * hx) / (gm * hm)
            a2 = 2.0 * math.atan2(sind, cosd)
            sum_c += gm * math.cos(a2)
            sum_s += gm * math.sin(a2)
            weight += gm
            band += 1
    r = math.hypot(sum_c, sum_s) / weight if weight > 0 else float('nan')   # 1 = every crest parallel to the shore, 0 = every direction
    # foam on the shore strip (water cells within 6 units of land)
    strip = covered = 0
    foam_max = 0.0
    for k in range(n * n):
        if land[k]:
            continue
        d = dist[k] * cell
        if d <= 6.0:
            strip += 1
            if foam[k] > 0.5:
                covered += 1
        foam_max = max(foam_max, foam[k])
    finite = all(math.isfinite(v) for v in h) and all(math.isfinite(v) for v in foam)
    return dict(time=rec['time'], alignment=r, strip_foam=(covered / strip if strip else 0.0), foam_max=foam_max, h_min=min(h), h_max=max(h), finite=finite, cells=band)


def cmd_metrics(folder):
    recs = waterrec.load(folder)
    if not recs:
        sys.exit('no captures in ' + folder)
    rows = [measure(r) for r in recs[-3:]]
    print('time   crest alignment (1 parallel .. 0 any)   shore strip foam   foam max   h min   h max')
    for m in rows:
        print('%5.1f  %.3f                                 %.3f              %.2f       %.3f  %.3f%s' % (m['time'], m['alignment'], m['strip_foam'], m['foam_max'], m['h_min'], m['h_max'], '' if m['finite'] else '  NOT FINITE'))
    return rows


def cmd_selftest(terrain):
    out = run(terrain=terrain, seconds=40.0, start=32.0, every=4.0, out=OUT + '_selftest', look=2)
    rows = [measure(r) for r in waterrec.load(out)]
    failures = []
    for m in rows:
        if not m['finite']:
            failures.append('not finite at t=%.1f' % m['time'])
        if not (m['h_min'] > -0.5 and m['h_max'] < 0.6):
            failures.append('height out of range at t=%.1f (%.3f .. %.3f)' % (m['time'], m['h_min'], m['h_max']))
        if not (m['alignment'] < 0.80):
            failures.append('crests too aligned with the shore at t=%.1f (%.3f, want < 0.80: a real sea is noisier)' % (m['time'], m['alignment']))
        if not (0.02 < m['strip_foam'] < 0.75):
            failures.append('shore foam coverage %.3f at t=%.1f outside 0.02 .. 0.75' % (m['strip_foam'], m['time']))
    for m in rows:
        print('t=%5.1f alignment %.3f strip foam %.3f foam max %.2f height %.3f .. %.3f' % (m['time'], m['alignment'], m['strip_foam'], m['foam_max'], m['h_min'], m['h_max']))
    if failures:
        print('FAIL')
        for f in failures:
            print('  ' + f)
        return 1
    print('PASS')
    return cmd_gate() or cmd_domains(SRC)


def cmd_gate():
    if not os.path.exists(EXE):
        sys.exit('build the lab first: tools/watersimlab/build.ps1')
    print('gate:', flush=True)
    return subprocess.run([EXE, '--gate']).returncode


def cmd_domains(src):
    if not os.path.exists(EXE):
        sys.exit('build the lab first: tools/watersimlab/build.ps1')
    print('domains:', flush=True)
    return subprocess.run([EXE, '--src', src, '--domains']).returncode


def cmd_strip(folder, out, crop):
    from PIL import Image
    files = sorted(f for f in os.listdir(folder) if f.startswith('look_') and f.endswith('.bmp'))
    ims = []
    for f in files[-4:]:
        im = Image.open(os.path.join(folder, f)).convert('RGB')
        if crop:
            im = im.crop(crop)
        ims.append(im)
    w, h = ims[0].size
    sheet = Image.new('RGB', (w * len(ims), h))
    for k, im in enumerate(ims):
        sheet.paste(im, (k * w, 0))
    sheet.save(out)
    print('wrote', out)


def read_series(folder):
    rows = []
    with open(os.path.join(folder, 'series.csv')) as f:
        header = f.readline().strip().split(',')
        for line in f:
            rows.append(dict(zip(header, (float(v) for v in line.strip().split(',')))))
    return rows


def read_rays(folder):
    """{time: {ray: [(r, h), ...]}}"""
    out = {}
    with open(os.path.join(folder, 'rays.csv')) as f:
        f.readline()
        for line in f:
            t, ray, r, h = line.strip().split(',')
            out.setdefault(round(float(t), 2), {}).setdefault(int(ray), []).append((float(r), float(h)))
    return out


def at_time(rows, t):
    return min(rows, key=lambda row: abs(row['time'] - t))


def extrema(profile, threshold):
    """Crests of a radial profile beyond 2 units: sign changes of the height that rise above +-threshold (a hysteresis, so noise does not count), halved."""
    changes = 0
    state = 0
    for r, h in profile:
        if r < 2.0:
            continue
        if h > threshold:
            if state < 0:
                changes += 1
            state = 1
        elif h < -threshold:
            if state > 0:
                changes += 1
            state = -1
    return changes / 2.0


def cmd_impact(args):
    out = args.out
    os.makedirs(out, exist_ok=True)
    extra = ['--impact', '--impact-size', str(args.size), '--impacts', str(args.impacts), '--impact-gap', str(args.gap),
             '--capillary', str(args.capillary), '--damping', str(args.damping), '--impact-scale', str(args.scale)]
    if args.visc >= 0:
        extra += ['--visc', str(args.visc)]
    if args.legacy:
        extra.append('--legacy')
    run('coast', args.seconds + 1.0, 100.0, 100.0, out, SRC, look=0, extra=extra)
    rows = read_series(out)
    rays = read_rays(out)
    peak = max(r['maxabs'] for r in rows)
    t_peak = max(rows, key=lambda r: r['maxabs'])['time']
    centre = [r for r in rows if 0.6 <= r['time'] <= args.seconds]
    centre_peak = max(abs(r['h0']) for r in rows if r['time'] <= 0.6) or 1e-9
    crossings = 0
    prev = None
    for r in centre:
        v = r['h0'] if abs(r['h0']) > 0.05 * centre_peak else None
        if v is not None:
            if prev is not None and (v > 0) != (prev > 0):
                crossings += 1
            prev = v
    late = [abs(r['h0']) for r in rows if 2.0 <= r['time'] <= 4.0]
    residual = (max(late) / centre_peak) if late else 0.0
    print('impact: size %.1f, %d impact(s) every %.2f s, %s model, capillary %d %%, damping %d %%' %
          (args.size, args.impacts, args.gap, 'legacy' if args.legacy else 'new', args.capillary, args.damping))
    print('  peak |height| %.3f at %.2f s;   middle: peak %.3f, sign changes after 0.6 s: %d, 2-4 s residual %.0f %% of the peak' %
          (peak, t_peak, centre_peak, crossings, 100.0 * residual))
    print('  volume (height x area):  ' + '  '.join('%.1fs %+.3f' % (t, at_time(rows, t)['volume']) for t in (0.5, 1.0, 2.0, 4.0, 7.0) if t <= args.seconds))
    print('  energy:                  ' + '  '.join('%.1fs %.2f' % (t, at_time(rows, t)['energy']) for t in (0.3, 1.0, 2.0, 4.0, 7.0) if t <= args.seconds))
    print('  front radius (units):    ' + '  '.join('%.1fs %.1f' % (t, at_time(rows, t)['front']) for t in (0.5, 1.0, 2.0, 4.0, 7.0) if t <= args.seconds))
    print('  foam (sum):              ' + '  '.join('%.1fs %.1f' % (t, at_time(rows, t)['foam']) for t in (0.3, 1.0, 2.0, 4.0, 7.0) if t <= args.seconds))
    print('  foam cells (> 0.5):      ' + '  '.join('%.1fs %d' % (t, at_time(rows, t)['foamcells']) for t in (0.3, 1.0, 2.0, 4.0, 7.0) if t <= args.seconds))
    print('  cells above 0.02:        ' + '  '.join('%.1fs %d' % (t, at_time(rows, t)['active']) for t in (0.5, 1.0, 2.0, 4.0, 7.0) if t <= args.seconds))
    rough = {}
    for t in (0.75, 1.5, 3.0):
        key = min(rays, key=lambda k: abs(k - t)) if rays else None
        if key is None:
            continue
        counts = [extrema(profile, 0.12 * max(abs(h) for _, h in profile)) for profile in rays[key].values()]
        rough[t] = sum(counts) / max(len(counts), 1)
    print('  crests along a ray (mean of 8 rays):  ' + '  '.join('%.2fs %.1f' % (t, c) for t, c in rough.items()))
    ok = True
    if args.check:
        checks = [
            ('the middle rings at most 5 times after 0.6 s', crossings <= 5),
            ('the middle has settled to < 25 % of its peak by 2-4 s', residual < 0.25),
            ('the splash has no volume (|volume| < 0.05 at 2 s)', abs(at_time(rows, 2.0)['volume']) < 0.05 if args.seconds >= 2.0 else True),
            ('waves have run out to 12 units by 3 s', at_time(rows, 3.0)['front'] >= 12.0 if args.seconds >= 3.0 else True),
            ('the peak is visible but not a wall (0.04 .. 1.2)', 0.04 <= peak <= 1.2),
        ]
        if args.size >= 5.0:
            checks.append(('white foam on the impact (cells > 0.5 at 0.3 s)', at_time(rows, 0.3)['foamcells'] >= 20))
            checks.append(('at least two crests on a ray by 3 s', rough.get(3.0, 0) >= 2.0))
        if args.impacts > 1:
            checks.append(('a salvo does not pile up (peak < 1.5x a single shell\'s 0.25 at size 5)', peak < 0.55))
        for name, passed in checks:
            print('  [%s] %s' % ('ok' if passed else 'FAIL', name))
            ok &= passed
        print('  checks:', 'ok' if ok else 'FAILED')
    return 0 if ok else 1


def cmd_wake(args):
    out = args.out
    os.makedirs(out, exist_ok=True)
    extra = ['--wake', '--hull-speed', str(args.speed), '--hull-length', str(args.length), '--hull-beam', str(args.beam),
             '--hull-radius', str(args.radius), '--wake-scale', str(args.scale)]
    if args.capillary != 100 or args.damping != 100:
        extra += ['--capillary', str(args.capillary), '--damping', str(args.damping)]
    if args.visc >= 0:
        extra += ['--visc', str(args.visc)]
    if args.hull_foam >= 0:
        extra += ['--hull-foam', str(args.hull_foam)]
    if args.body:
        extra += ['--body', '--hull-draft', str(args.draft), '--body-foam', str(args.body_foam)]
        if args.body_push >= 0:
            extra += ['--body-push', str(args.body_push)]
    if args.foam_kept >= 0:
        extra += ['--foam-kept', str(args.foam_kept)]
    run('coast', args.seconds, 1.0, 5.0, out, SRC, look=args.look, extra=extra)
    rows = []
    with open(os.path.join(out, 'wake.csv')) as f:
        header = f.readline().strip().split(',')
        for line in f:
            rows.append(dict(zip(header, (float(v) for v in line.strip().split(',')))))
    last = max(r['time'] for r in rows)
    print('wake: hull speed %.1f, half length %.1f, half beam %.2f, radius %.1f, wake scale %.1f; table at t=%.1f s (hull at x=%.0f)' %
          (args.speed, args.length, args.beam, args.radius, args.scale, last, [r['hullx'] for r in rows if r['time'] == last][0]))
    print('  behind(u)  |h| max   lateral(u)  foam max  foam width(u)')
    for r in [r for r in rows if r['time'] == last]:
        print('  %6.0f     %.3f     %+6.1f      %.2f      %5.1f' % (r['d'], r['hmax'], r['lat'], r['foammax'], r['foamwidth']))
    ok = True
    if args.check:
        final = {r['d']: r for r in rows if r['time'] == last}
        checks = [
            ('waves of at least 0.15 behind the stern (8 u)', final[8.0]['hmax'] >= 0.15),
            ('white foam (> 0.8) 8 u behind', final[8.0]['foammax'] > 0.8),
            ('foam still above 0.2 at 22 u (a trail of a few seconds, close behind the ship)', final[22.0]['foammax'] > 0.2),
            ('the trail is wider than the hull (foam width at 14 u > 6 u)', final[14.0]['foamwidth'] > 6.0),
        ]
        for name, passed in checks:
            print('  [%s] %s' % ('ok' if passed else 'FAIL', name))
            ok &= passed
        print('  checks:', 'ok' if ok else 'FAILED')
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('run')
    r.add_argument('--terrain', default='coast')
    r.add_argument('--seconds', type=float, default=40.0)
    r.add_argument('--from', dest='start', type=float, default=20.0)
    r.add_argument('--every', type=float, default=4.0)
    r.add_argument('--out', default=OUT)
    r.add_argument('--src', default=SRC)
    m = sub.add_parser('metrics')
    m.add_argument('dir')
    t = sub.add_parser('selftest')
    t.add_argument('--terrain', default='coast')
    sub.add_parser('gate')
    d = sub.add_parser('domains')
    d.add_argument('--src', default=SRC)
    s = sub.add_parser('strip')
    s.add_argument('dir')
    s.add_argument('-o', default='strip.png')
    s.add_argument('--crop', default='')
    i = sub.add_parser('impact')
    i.add_argument('--size', type=float, default=6.0)
    i.add_argument('--impacts', type=int, default=1)
    i.add_argument('--gap', type=float, default=0.25)
    i.add_argument('--seconds', type=float, default=8.0)
    i.add_argument('--legacy', action='store_true')
    i.add_argument('--capillary', type=int, default=100)
    i.add_argument('--damping', type=int, default=100)
    i.add_argument('--check', action='store_true')
    i.add_argument('--scale', type=float, default=1.0)
    i.add_argument('--visc', type=float, default=-1.0)
    i.add_argument('--out', default=os.path.join(LAB_ROOT, 'lab_impact', 'run'))
    wk = sub.add_parser('wake')
    wk.add_argument('--speed', type=float, default=5.0)
    wk.add_argument('--length', type=float, default=2.9)
    wk.add_argument('--beam', type=float, default=0.6)
    wk.add_argument('--radius', type=float, default=3.4)
    wk.add_argument('--scale', type=float, default=2.0)
    wk.add_argument('--seconds', type=float, default=40.0)
    wk.add_argument('--capillary', type=int, default=100)
    wk.add_argument('--damping', type=int, default=100)
    wk.add_argument('--visc', type=float, default=-1.0)
    wk.add_argument('--look', type=int, default=4)
    wk.add_argument('--check', action='store_true')
    wk.add_argument('--hull-foam', type=float, default=-1.0)
    wk.add_argument('--body', action='store_true', help='the hull is a volume that displaces the water (HullDisplacement.h), not the hand-made wake')
    wk.add_argument('--draft', type=float, default=1.2)
    wk.add_argument('--body-push', type=float, default=-1.0)
    wk.add_argument('--body-foam', type=float, default=1.0)
    wk.add_argument('--foam-kept', type=float, default=-1.0)
    wk.add_argument('--out', default=os.path.join(LAB_ROOT, 'lab_wake', 'run'))
    a = ap.parse_args()
    if a.cmd == 'wake':
        sys.exit(cmd_wake(a))
    if a.cmd == 'impact':
        sys.exit(cmd_impact(a))
    if a.cmd == 'run':
        run(a.terrain, a.seconds, a.start, a.every, a.out, a.src)
    elif a.cmd == 'metrics':
        cmd_metrics(a.dir)
    elif a.cmd == 'gate':
        sys.exit(cmd_gate())
    elif a.cmd == 'domains':
        sys.exit(cmd_domains(a.src))
    elif a.cmd == 'selftest':
        sys.exit(cmd_selftest(a.terrain))
    elif a.cmd == 'strip':
        cmd_strip(a.dir, a.o, tuple(int(v) for v in a.crop.split(',')) if a.crop else None)


if __name__ == '__main__':
    main()
