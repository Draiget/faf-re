import sys, re, os, statistics as st
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # tools/perf_audit
import perf_parse as pp
L = os.environ.get('FAF_LOGS', 'C:/ProgramData/FAForever/logs').replace(chr(92), '/') + '/'
tag = sys.argv[1]; reps = int(sys.argv[2]); labels = sys.argv[3].split(',')
for label in labels:
    print('#### ', label)
    agg = {}
    for r in range(reps):
        p = L + 'pf_%s_%s_r%d_d3d12_perf.log' % (tag, label, r)
        if not os.path.exists(p):
            continue
        steps, pre = pp.parse(p)
        for s in steps:
            wins = s['wins']
            mx = max([w.get('max', 0) for w in wins] or [0])
            over = sum(w.get('over', 0) for w in wins)
            res = pp.step_stats(s)
            if not res:
                continue
            a = agg.setdefault(s['label'], {'max': [], 'over': [], 'gpu': [], 'cpu': [], 'collect': [], 'feed': [], 'frame_hi': []})
            a['max'].append(mx); a['over'].append(over); a['gpu'].append(res['gpu']); a['cpu'].append(res['cpu'])
            a['collect'].append(res['passes'].get('LightsCollect', (0, 0))[0]); a['feed'].append(res['passes'].get('LightsFeed', (0, 0))[0])
        txt = open(p, errors='replace').read()
        rd = [(int(m.group(1)), float(m.group(2))) for m in re.finditer(r'DynLights: (\d+) textures read this frame in ([\d.]+) ms', txt)]
        wk = [(int(m.group(1)), float(m.group(2))) for m in re.finditer(r'DynLights: (\d+) textures read on the worker in ([\d.]+) ms', txt)]
        agg.setdefault('_reads', []).append((len(rd), max([x[1] for x in rd] or [0]), sum(x[1] for x in rd), len(wk), max([x[1] for x in wk] or [0])))
    for lab, a in agg.items():
        if lab == '_reads':
            print('render-thread read frames (count, worst ms, total ms) / worker frames (count, worst ms) per run:', a)
            continue
        f = lambda xs: ' '.join('%.2f' % x for x in xs)
        print('%-14s max frame ms %s | frames over: %s | gpu %s | cpu %s | LightsCollect cpu %s' % (lab, ' '.join('%.1f' % x for x in a['max']), a['over'], f(a['gpu']), f(a['cpu']), f(a['collect'])))
