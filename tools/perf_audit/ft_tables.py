import os
"""ft_tables.py [tag=ft] -> markdown of the per-feature cost tables (one per scene and API) and the ranking per API.
Logs: logs/pf_<tag>_<scene>_<api>_perf.log"""
import glob, os, re, sys, collections
sys.path.insert(0, os.path.dirname(__file__))
import feat_report as fr

tag = sys.argv[1] if len(sys.argv) > 1 else 'ft'
exe = sys.argv[2] if len(sys.argv) > 2 else 'perf'
LOGS = os.environ.get('FAF_LOGS', 'C:/ProgramData/FAForever/logs')
ORDER = ['lights', 'lightsU', 'shadowfilter', 'cascades', 'ao', 'aa', 'sharpen', 'grade', 'aastack', 'taa', 'rscale', 'softp', 'lowres', 'bloomwide', 'atmosphere', 'aniso', 'waterq', 'watersim', 'ssr',
         'caustics', 'absorb', 'sheen', 'unitshadows', 'banks', 'river', 'terrainwl', 'shoretess', 'waterfalls', 'waterall', 'rays', 'cfg']
res = {}
for log in sorted(glob.glob('%s/pf_%s_*_%s.log' % (LOGS, tag, exe))):
    m = re.match(r'pf_%s_(\w+?)_(d3d11|d3d12|vulkan)_%s\.log' % (tag, exe), os.path.basename(log))
    if not m:
        continue
    scene, api = m.group(1), m.group(2)
    res[(api, scene)] = fr.analyse(log)


def fmt(r, k):
    d = r.get(k + '_d')
    if d is None:
        return '-'
    lo, hi = r[k + '_d_rng']
    return '%+.3f [%+.3f, %+.3f]' % (d, lo, hi)


rank = collections.defaultdict(dict)
for (api, scene), rows in sorted(res.items()):
    print('\n### %s, %s\n' % (scene, api))
    base = [r for r in rows if r['feature'] == 'cfg' and r['level'] == 'off']
    if base:
        print('Everything off: GPU %.3f ms, CPU %.3f ms, wall %.3f ms (frame wall p99 %.2f ms).\n' % (base[0]['gpu'], base[0]['cpu'], base[0]['wall'], base[0]['p99']))
    print('| feature | level | GPU ms (abs) | GPU ms vs off [min, max of 3] | CPU ms vs off | wall ms vs off | biggest passes (GPU ms, CPU ms) |')
    print('|---|---|---|---|---|---|---|')
    if base:
        for r in rows:
            if r['feature'] == 'cfg' and r['level'] != 'off':
                for k in ('gpu', 'cpu', 'wall', 'p99'):
                    r[k + '_d'] = r[k] - base[0][k]
                    r[k + '_d_rng'] = (r[k + '_rng'][0] - base[0][k], r[k + '_rng'][1] - base[0][k])
    rows = [r for r in rows if r['level'] != 'off']
    rows.sort(key=lambda r: (ORDER.index(r['feature']) if r['feature'] in ORDER else 99, r['level']))
    for r in rows:
        top = ', '.join('%s %+.3f/%+.3f' % t for t in r['top'][:3])
        print('| %s | %s | %.3f | %s | %s | %s | %s |' % (r['feature'], r['level'], r['gpu'], fmt(r, 'gpu'), fmt(r, 'cpu').split(' ')[0], fmt(r, 'wall').split(' ')[0], top))
        if r.get('gpu_d') is not None and r['feature'] != 'cfg':
            rank[api].setdefault((r['feature'], r['level']), {})[scene] = (r['gpu_d'], r.get('cpu_d', 0.0))
print('\n## Ranking (worst scene of each feature level, GPU ms/frame over everything off)\n')
for api, d in sorted(rank.items()):
    print('\n### %s\n' % api)
    print('| # | feature | level | worst scene | GPU ms | CPU ms | all scenes (GPU ms) |')
    print('|---|---|---|---|---|---|---|')
    items = sorted(d.items(), key=lambda kv: -max(v[0] for v in kv[1].values()))
    for i, ((f, lv), sc) in enumerate(items[:14], 1):
        worst = max(sc.items(), key=lambda kv: kv[1][0])
        print('| %d | %s | %s | %s | %+.3f | %+.3f | %s |' % (i, f, lv, worst[0], worst[1][0], worst[1][1], ', '.join('%s %+.2f' % (s, v[0]) for s, v in sorted(sc.items()))))
