"""cost_report.py: tables of the cost runs (out/cost/<build>_<cfg>_d3d12_r1/game.log)"""
import os, re, sys, statistics as st, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))   # tools/perf_audit: perf_parse.py
import perf_parse as pp

def q(v, p):
    v = sorted(v)
    if not v: return float('nan')
    k = (len(v) - 1) * p
    f = int(k); c = min(f + 1, len(v) - 1)
    return v[f] + (v[c] - v[f]) * (k - f)

def run_stats(d):
    log = os.path.join(d, 'game.log')
    if not os.path.exists(log): return None
    steps, pre = pp.parse(log)
    wins = [w for s in steps for w in s['wins']]
    skip = 0.0; k = 0
    while k < len(wins) - 1 and skip < 3.0:       # drop the first 3 s
        skip += wins[k]['wall'] * wins[k]['frames'] / 1000.0; k += 1
    wins = wins[k:]
    if not wins: return None
    gpu = [w['gpu'] for w in wins]; cpu = [w.get('cpu', float('nan')) for w in wins]
    passes = {}
    for n in set(x for w in wins for x in w['passes']):
        passes[n] = {'cpu': st.median([w['passes'].get(n, (0, 0, 0))[0] for w in wins]), 'gpu': st.median([w['passes'].get(n, (0, 0, 0))[1] for w in wins]),
                     'draws': st.median([w['passes'].get(n, (0, 0, 0))[2] for w in wins])}
    txt = open(log, errors='replace').read()
    m = re.findall(r'budget: local ([\d.]+) / ([\d.]+) MB used', txt)
    return {'windows': len(wins), 'frames': sum(w['frames'] for w in wins), 'gpu_med': st.median(gpu), 'gpu_p95': q(gpu, 0.95), 'cpu_med': st.median(cpu), 'cpu_p95': q(cpu, 0.95),
            'wall_med': st.median([w['wall'] for w in wins]), 'p99_med': st.median([w.get('p99', float('nan')) for w in wins]),
            'vram_mb': float(m[-1][0]) if m else None, 'passes': passes}

if __name__ == '__main__':
    base = os.path.join(HERE, 'out', 'cost')
    res = {}
    for name in sorted(os.listdir(base)):
        r = run_stats(os.path.join(base, name))
        if r: res[name] = r
    json.dump(res, open(os.path.join(base, 'cost.json'), 'w'), indent=1)
    for n, r in res.items():
        print(n, {k: (round(v, 2) if isinstance(v, float) else v) for k, v in r.items() if k != 'passes'})
