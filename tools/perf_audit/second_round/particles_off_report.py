import sys, os, statistics as st
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # tools/perf_audit
import perf_parse as pp
L = os.environ.get('FAF_LOGS', 'C:/ProgramData/FAForever/logs').replace(chr(92), '/') + '/'
pre = sys.argv[1]; api = sys.argv[2]; reps = int(sys.argv[3]); labs = sys.argv[4].split(',')
for view in ('meas1', 'meas2'):
    print('==', view)
    for lab in labs:
        exe = 'perfbase' if lab == 'base' else 'perf'
        v = {'gpu': [], 'cpu': [], 'EffP': [], 'draws': []}
        for r in range(reps):
            p = L + 'pf_%s_%s_r%d_%s_%s.log' % (pre, lab, r, api, exe)
            if not os.path.exists(p):
                continue
            try:
                d = pp.by_label(pp.parse(p)[0])[view][0]
            except Exception as e:
                continue
            v['gpu'].append(d['gpu']); v['cpu'].append(d['cpu']); v['draws'].append(d['draws'])
            v['EffP'].append(d['passes'].get('EffParticles', (0, 0))[1])
        f = lambda xs: ' '.join('%.3f' % x for x in xs) + ('  med %.3f' % st.median(xs) if xs else '')
        print('%-8s n=%d GPU %s | EffParticles GPU %s | CPU %s | draws %s' % (lab, len(v['gpu']), f(v['gpu']), f(v['EffP']), f(v['cpu']), f(v['draws'])))
