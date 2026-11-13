"""vramiso_report.py -> the memory of atmosphere, temporal AA and render scale switched on alone, in this order (after all off), D3D12 and Vulkan."""
import json, os, statistics as st, sys
sys.path.insert(0, os.path.dirname(__file__))
import gen_steps_cmds as g

OUT = (os.environ.get('PERF_AUDIT_OUT', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'out')).replace(chr(92), '/')) + '/perf_out'
cols = {}
for api in ('d3d12', 'vulkan'):
    jf = '%s/vramiso_%s_perf.json' % (OUT, api)
    if not os.path.exists(jf):
        continue
    j = json.load(open(jf))
    mem = j['mem']
    t0 = j['markers']['first_step']
    lst = g.vram_steps(api)[:3] + [('atmosphere', 0), ('taa', 0), ('renderscale_75', 0), ('final_hold', 0)]
    prev = None
    for k, (lab, _) in enumerate(lst):
        a, b = t0 + 3 + 7 * k + 3.5, t0 + 3 + 7 * k + 7
        pts = [s for s in mem if a <= s['t'] <= b]
        if not pts:
            continue
        priv = st.median(s['priv'] for s in pts)
        gp = [s['gpu'] for s in pts if s.get('gpu', -1) >= 0]
        gpu = st.median(gp) if gp else float('nan')
        cols.setdefault(lab, {})[api] = (priv - prev[0] if prev else 0.0, gpu - prev[1] if prev else 0.0, gpu)
        prev = (priv, gpu)
print('| step (each alone, in this order, after all off) | Direct3D 12: process MB delta | GPU MB delta (total) | Vulkan: process MB delta | GPU MB delta (total) |')
print('|---|---|---|---|---|')
for lab in ('all_off', 'hold_off', 'atmosphere', 'taa', 'renderscale_75', 'final_hold'):
    r = cols.get(lab, {})
    c = []
    for api in ('d3d12', 'vulkan'):
        v = r.get(api)
        c += ['%+.0f' % v[0], '%+.0f (%.0f)' % (v[1], v[2])] if v else ['n/a', 'n/a']
    print('| %s | %s |' % (lab, ' | '.join(c)))
