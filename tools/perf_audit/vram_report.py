import os
"""vram_report.py -> memory per feature: the step labels come from the steps file, the time of a step from the log marker of the first step plus the holds"""
import json, os, re, statistics as st, sys

sys.path.insert(0, os.path.dirname(__file__))
import gen_steps_cmds as g

OUT = (os.environ.get('PERF_AUDIT_OUT', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'out')).replace(chr(92), '/')) + '/perf_out'
for api in ('d3d12', 'vulkan'):
    jf = '%s/vram_%s_perf.json' % (OUT, api)
    if not os.path.exists(jf):
        continue
    j = json.load(open(jf))
    mem = j['mem']
    t0 = j['markers']['first_step']
    steps = g.vram_steps(api)
    print('\n### %s\n' % api)
    print('| step (cumulative) | process private MB | delta | GPU dedicated MB | delta |')
    print('|---|---|---|---|---|')
    prev = None
    for k, (lab, cmds) in enumerate(steps):
        a = t0 + 3 + 7 * k + 3.5   # the last 3.5 s of the step
        b = t0 + 3 + 7 * k + 7
        pts = [s for s in mem if a <= s['t'] <= b]
        if not pts:
            continue
        priv = st.median(s['priv'] for s in pts)
        gp = [s['gpu'] for s in pts if s.get('gpu', -1) >= 0]
        gpu = st.median(gp) if gp else float('nan')
        dp = priv - prev[0] if prev else 0.0
        dg = gpu - prev[1] if prev else 0.0
        print('| %s | %.0f | %+.0f | %.0f | %+.0f |' % (lab, priv, dp, gpu, dg))
        prev = (priv, gpu)
