"""umb_report.py -> where the video memory of the user's profile goes: the profile with one group of its options at the default (jobs.py umb, mk_prefs_umb.py)."""
import json, os, statistics as st

OUT = (os.environ.get('PERF_AUDIT_OUT', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'out')).replace(chr(92), '/')) + '/perf_out'
DESC = {'all': 'the user profile as it is', 'nolights': 'dynamic lights at the default (off)', 'noshadow': 'shadow filtering at the default (off)', 'noao': 'ambient occlusion at the default (Standard)',
        'nosoft': 'soft particles at the default (Low)', 'nosharp': 'sharpening quality at the default (Medium)', 'less3': 'lights, shadow filtering and AO at the default'}
print('| run (Direct3D 12, lake scene, settled) | process private MB | GPU dedicated MB | GPU MB against the whole profile |')
print('|---|---|---|---|')
ref = None
for lab in DESC:
    jf = '%s/umb2_%s_d3d12_perf.json' % (OUT, lab)
    if not os.path.exists(jf):
        continue
    j = json.load(open(jf))
    t0 = j['markers']['first_step']
    late = [s for s in j['mem'] if s['t'] >= t0 + 10]
    priv = st.median(s['priv'] for s in late)
    gpu = st.median(s['gpu'] for s in late if s.get('gpu', -1) >= 0)
    if ref is None:
        ref = gpu
    print('| %s | %.0f | %.0f | %+.0f |' % (DESC[lab], priv, gpu, gpu - ref))
