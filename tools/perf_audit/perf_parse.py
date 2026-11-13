"""perf_parse.py <log> -> list of steps with windows. import and use parse(log) / summarize."""
import re, statistics as st, sys, json
def parse(path):
    steps = []   # {i,label,wins:[{wall,gpu,p50,p99,max,over,cpu,passes{}}]}
    cur = None; win = None; pre = []
    for l in open(path, errors='replace'):
        m = re.search(r'PERF: step (\d+) (\S+)', l)
        if m:
            cur = {'i': int(m.group(1)), 'label': m.group(2), 'wins': []}; steps.append(cur); win = None; continue
        m = re.search(r'Render profile over (\d+) frames: ([\d.]+) ms/frame wall, GPU ([\d.]+) ms/frame, ([\d.]+) draws, ([\d.]+) state changes, ([\d.]+) KB', l)
        if m:
            win = {'frames': int(m.group(1)), 'wall': float(m.group(2)), 'gpu': float(m.group(3)), 'draws': float(m.group(4)), 'sc': float(m.group(5)), 'kb': float(m.group(6)), 'passes': {}}
            (cur['wins'] if cur else pre).append(win); continue
        m = re.search(r'frame wall p50 ([\d.]+) ms, p99 ([\d.]+) ms, max ([\d.]+) ms, (\d+) of (\d+) frames over', l)
        if m and win is not None:
            win.update(p50=float(m.group(1)), p99=float(m.group(2)), max=float(m.group(3)), over=int(m.group(4))); continue
        m = re.search(r'pass (\S+)\s+([\d.]+) calls\s+CPU\s+([\d.]+) ms\s+GPU\s+([\d.]+) ms per frame,\s+([\d.]+) draws', l)
        if m and win is not None:
            win['passes'][m.group(1)] = (float(m.group(3)), float(m.group(4)), float(m.group(5)))
            if m.group(1) == 'Frame': win['cpu'] = float(m.group(3))
    return steps, pre
SKIP_SECONDS = 1.2
def med(v): return st.median(v) if v else float('nan')
def step_stats(s, skip=2):
    wins = s['wins']; acc = 0.0; k = 0
    while k < len(wins) - 1 and acc < SKIP_SECONDS:
        acc += wins[k]['wall'] * wins[k]['frames'] / 1000.0; k += 1
    w = wins[k:]
    if not w: return None
    r = {'n': len(w)}
    for k in ('wall', 'gpu', 'cpu', 'p50', 'p99', 'draws', 'sc', 'kb'):
        r[k] = med([x.get(k, float('nan')) for x in w])
    r['max'] = max(x.get('max', 0) for x in w)
    r['over'] = sum(x.get('over', 0) for x in w)
    passes = {}
    names = set(n for x in w for n in x['passes'])
    for n in names:
        passes[n] = (med([x['passes'].get(n, (0, 0, 0))[0] for x in w]), med([x['passes'].get(n, (0, 0, 0))[1] for x in w]))
    r['passes'] = passes
    return r
def by_label(steps, skip=2):
    """label -> list of per-step stats (one per repeat; labels may repeat)"""
    d = {}
    for s in steps:
        r = step_stats(s, skip)
        if r: d.setdefault(s['label'], []).append(r)
    return d
if __name__ == '__main__':
    steps, pre = parse(sys.argv[1])
    d = by_label(steps)
    for lab, rs in d.items():
        print('%-28s n=%d gpu %s cpu %s wall %s p99 %s' % (lab, len(rs), ' '.join('%.2f' % r['gpu'] for r in rs), ' '.join('%.2f' % r['cpu'] for r in rs), ' '.join('%.2f' % r['wall'] for r in rs), ' '.join('%.1f' % r['p99'] for r in rs)))
