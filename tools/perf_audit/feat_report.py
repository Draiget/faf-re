"""feat_report.py <log> [<log> ...] -> per-feature cost table. A level step 'f.L' is compared with the 'f.off' step that precedes it in the same
repetition block. Prints (and returns) rows: scene/api, feature, level, gpu diff median [min,max], cpu diff, wall diff, top passes (GPU diff)."""
import sys, statistics as st, json, os
sys.path.insert(0, os.path.dirname(__file__))
import perf_parse as pp


def analyse(log):
    steps, pre = pp.parse(log)
    rows = {}
    lastoff = {}
    for s in steps:
        r = pp.step_stats(s)
        if r is None:
            continue
        lab = s['label']
        if '.' not in lab:
            continue
        f, lv = lab.split('.', 1)
        if f == 'cfg':
            rows.setdefault(('cfg', lv), []).append((r, None))
            continue
        if lv == 'off':
            lastoff[f] = r
            rows.setdefault((f, 'off'), []).append((r, None))
        elif f in lastoff:
            rows.setdefault((f, lv), []).append((r, lastoff[f]))
    out = []
    for (f, lv), lst in rows.items():
        def vals(k):
            return [x[0][k] for x in lst]
        def diffs(k):
            return [x[0][k] - x[1][k] for x in lst if x[1] is not None]
        row = {'feature': f, 'level': lv, 'n': len(lst)}
        for k in ('gpu', 'cpu', 'wall', 'p99'):
            v = vals(k)
            row[k] = st.median(v)
            row[k + '_rng'] = (min(v), max(v))
            d = diffs(k)
            if d:
                row[k + '_d'] = st.median(d)
                row[k + '_d_rng'] = (min(d), max(d))
        row['max'] = max(x[0]['max'] for x in lst)
        # passes: diff of the GPU ms of every pass against the off step, median over the blocks
        pd = {}
        for r, off in lst:
            if off is None:
                continue
            for n in set(r['passes']) | set(off['passes']):
                a = r['passes'].get(n, (0, 0))
                b = off['passes'].get(n, (0, 0))
                pd.setdefault(n, []).append((a[1] - b[1], a[0] - b[0]))
        top = sorted(((st.median([x[0] for x in v]), st.median([x[1] for x in v]), n) for n, v in pd.items()), key=lambda t: -abs(t[0]))[:4]
        row['top'] = [(n, round(g, 3), round(c, 3)) for g, c, n in top if abs(g) >= 0.005 or abs(c) >= 0.02]
        out.append(row)
    return out


if __name__ == '__main__':
    for log in sys.argv[1:]:
        print('==', os.path.basename(log))
        for r in analyse(log):
            if r['level'] == 'off' and r['feature'] != 'cfg':
                continue
            d = r.get('gpu_d')
            print('%-14s %-18s n=%d gpu %.3f %s dGPU %s dCPU %s dWall %s top %s' % (
                r['feature'], r['level'], r['n'], r['gpu'], '[%.3f,%.3f]' % r['gpu_rng'],
                ('%+.3f [%+.3f,%+.3f]' % ((d,) + r['gpu_d_rng'])) if d is not None else '-',
                ('%+.3f' % r['cpu_d']) if 'cpu_d' in r else '-', ('%+.3f' % r['wall_d']) if 'wall_d' in r else '-', r['top']))
