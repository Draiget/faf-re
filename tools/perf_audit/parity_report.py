"""parity_report.py <jsonl> -> markdown: for every (cfg, api, scene, view) the median over the repetitions of ours and the baseline and the difference."""
import json, sys, statistics as st, collections

rows = [json.loads(l) for l in open(sys.argv[1])]
grp = collections.defaultdict(list)
for r in rows:
    grp[(r['cfg'], r['api'], r['scene'], r['exe'])].append(r)


def med(lst, f):
    v = [f(r) for r in lst]
    v = [x for x in v if x is not None and x == x]
    return (st.median(v), min(v), max(v)) if v else (float('nan'),) * 3


def metric(view, key):
    return lambda r: r.get(view, {}).get(key)


out = []
keys = sorted(set((k[0], k[1], k[2]) for k in grp), key=lambda k: (['off', 'default', 'user'].index(k[0]), k[1], k[2]))
print('| cfg | api | scene | view | GPU ms base | GPU ms ours | CPU ms base | CPU ms ours | wall ms base | wall ms ours | p99 base | p99 ours | n |')
print('|---|---|---|---|---|---|---|---|---|---|---|---|---|')
for cfg, api, scene in keys:
    for view in ('meas1', 'meas2'):
        b = grp.get((cfg, api, scene, 'perfbase'), [])
        o = grp.get((cfg, api, scene, 'perf'), [])
        if not b or not o:
            continue
        cells = []
        for key in ('gpu', 'cpu', 'wall', 'p99'):
            mb, ob = med(b, metric(view, key)), med(o, metric(view, key))
            cells.append('%.3f' % mb[0])
            cells.append('%.3f (%+.3f)' % (ob[0], ob[0] - mb[0]))
        print('| %s | %s | %s | %s | %s | %d/%d |' % (cfg, api, scene, view, ' | '.join(cells), len(b), len(o)))
print()
print('| cfg | api | scene | private MB base | private MB ours | heap MB base/ours | GPU local MB base/ours | renderer_ready | shaders_compiled | sim_init | first_profile |')
print('|---|---|---|---|---|---|---|---|---|---|---|')
for cfg, api, scene in keys:
    b = grp.get((cfg, api, scene, 'perfbase'), [])
    o = grp.get((cfg, api, scene, 'perf'), [])
    if not b or not o:
        continue
    pb, po = med(b, lambda r: r.get('proc_private_mb')), med(o, lambda r: r.get('proc_private_mb'))
    hb, ho = med(b, lambda r: r.get('heap_mb')), med(o, lambda r: r.get('heap_mb'))
    gb, go = med(b, lambda r: r.get('gpu_local_mb')), med(o, lambda r: r.get('gpu_local_mb'))
    mk = []
    for m in ('renderer_ready', 'shaders_compiled', 'sim_init', 'first_profile'):
        mb, mo = med(b, lambda r, m=m: r.get('markers', {}).get(m)), med(o, lambda r, m=m: r.get('markers', {}).get(m))
        mk.append('%.2f / %.2f' % (mb[0], mo[0]))
    print('| %s | %s | %s | %.0f | %.0f (%+.0f) | %.0f / %.0f | %.0f / %.0f | %s |' % (cfg, api, scene, pb[0], po[0], po[0] - pb[0], hb[0], ho[0], gb[0], go[0], ' | '.join(mk)))
