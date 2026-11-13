"""lights_memory.py <tag> <levels>: video and process memory of the lake scene settled after the lights are switched on live at each given level (one run per level)"""
import sys, os, json, statistics as st
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # tools/perf_audit
import jobs
tag = sys.argv[1]; levels = [int(x) for x in sys.argv[2].split(',')]
for lv in levels:
    name = 'steps_%s_%d.lua' % (tag, lv)
    with open(jobs.HERE + '/' + name, 'w') as o:
        o.write("AB_PRESETS = { lake = { 60, 0.9, 0, -25, 0 } }\nAB_STEPS = {\n")
        o.write("  { 'start', {}, 'lake', 7 },\n  { 'on', { 'ren_DynLights %d' }, 'lake', 7 },\n  { 'c', {}, 'lake', 7 },\n  { 'd', {}, 'lake', 7 },\n}\n" % lv)
    t = '%s_l%d' % (tag, lv)
    jobs.run('perf', 'd3d12', t, 'lake', name, prefs='default', mem=1, hold=7, interval=500, timeout=900, con='sc_FrameTimeClamp=0')
    j = json.load(open('%s/perf_out/%s_d3d12_perf.json' % (jobs.S, t)))
    t0 = j['markers']['first_step']
    base = [s for s in j['mem'] if t0 + 3 + 3.5 <= s['t'] <= t0 + 3 + 7]
    pts = [s for s in j['mem'] if t0 + 3 + 14 + 3.5 <= s['t'] <= t0 + 3 + 28]
    gb = [s['gpu'] for s in base if s.get('gpu', -1) >= 0]
    gp = [s['gpu'] for s in pts if s.get('gpu', -1) >= 0]
    print('level %d: before the switch GPU %.0f MB; settled GPU dedicated %.0f MB (%+.0f), private %.0f MB (%+.0f)' % (
        lv, st.median(gb), st.median(gp), st.median(gp) - st.median(gb), st.median(s['priv'] for s in pts), st.median(s['priv'] for s in pts) - st.median(s['priv'] for s in base)))
