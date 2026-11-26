import os
"""soak_report.py -> table of the soak runs: memory growth (private bytes, GPU dedicated) over the run, hitches over 20 ms, frame percentiles."""
import glob, json, os, re, statistics as st, sys
sys.path.insert(0, os.path.dirname(__file__))
import perf_parse as pp

LOGS = os.environ.get('FAF_LOGS', 'C:/ProgramData/FAForever/logs')
OUT = (os.environ.get('PERF_AUDIT_OUT', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'out')).replace(chr(92), '/')) + '/perf_out'


def slope(points):
    # least squares MB per minute over (t seconds, MB)
    if len(points) < 4:
        return float('nan')
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    mx, my = st.mean(xs), st.mean(ys)
    den = sum((x - mx) ** 2 for x in xs)
    return 60.0 * sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den if den else float('nan')


print('| run | build / API / config | frames (windows) | median GPU ms | median CPU ms | frame p99 median ms | worst frame ms | windows with a frame over 20 ms | private MB start -> end (MB/min) | GPU dedicated MB start -> end (MB/min) |')
print('|---|---|---|---|---|---|---|---|---|---|')
for jf in sorted(glob.glob(OUT + '/soak_*.json')):
    base = os.path.basename(jf)[:-5]
    m = re.match(r'soak_(\w+)_(d3d11|d3d12|vulkan)_(perf|perfbase)$', base)
    if not m:
        continue
    label, api, exe = m.groups()
    log = '%s/pf_soak_%s_%s_%s.log' % (LOGS, label, api, exe)
    if not os.path.exists(log):
        continue
    steps, pre = pp.parse(log)
    wins = [w for s in steps if s['label'].startswith('soak.') for w in s['wins']]
    if not wins:
        continue
    j = json.load(open(jf))
    mem = j.get('mem', [])
    t0 = mem[0]['t'] if mem else 0
    # drop the first 30 s of the run and the loading phase: the growth is read from the soak steps' time range
    start = next((x['t'] for x in mem if x['t'] >= j['markers'].get('first_step', 0) + 6), None)
    priv = [(x['t'], x['priv']) for x in mem if start is not None and x['t'] >= start]
    gpu = [(x['t'], x['gpu']) for x in mem if start is not None and x['t'] >= start and x.get('gpu', -1) >= 0]
    over = [w for w in wins if w.get('max', 0) > 20]
    print('| %s | %s / %s | %d (%d) | %.2f | %.2f | %.2f | %.1f | %d | %.0f -> %.0f (%+.1f) | %s |' % (
        label, 'baseline' if exe == 'perfbase' else 'ours', api, sum(w['frames'] for w in wins), len(wins), st.median(w['gpu'] for w in wins), st.median(w.get('cpu', 0) for w in wins),
        st.median(w.get('p99', 0) for w in wins), max(w.get('max', 0) for w in wins), len(over), priv[0][1] if priv else 0, priv[-1][1] if priv else 0, slope(priv),
        ('%.0f -> %.0f (%+.1f)' % (gpu[0][1], gpu[-1][1], slope(gpu))) if gpu else 'n/a'))
