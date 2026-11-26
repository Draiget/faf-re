"""river_ab.py <apis> <tag> [cfg]: the river map at the falls and wide, default config; A/B in one session by switches
(ren_WaterBodyHold on/off, ren_Shoreline, ren_WaterSim). Reads the passes of every step."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # tools/perf_audit
import jobs, parity
apis = sys.argv[1].split(','); tag = sys.argv[2]; cfg = sys.argv[3] if len(sys.argv) > 3 else 'default'
exe = sys.argv[4] if len(sys.argv) > 4 else 'perf'
pres = "fall = { 38, 0.45, 3.14, 0, 0, 0 }, wide = { 90, 0.8, 3.14, 0, 0, 0 }"
H = 8
steps = []
for p in ('fall', 'wide'):
    for rep in range(2):
        steps.append(('%s_holdoff%d' % (p, rep), ['ren_WaterBodyHold 0'], p, H))
        steps.append(('%s_holdon%d' % (p, rep), ['ren_WaterBodyHold 1'], p, H))
    steps.append(('%s_noshore' % p, ['ren_Shoreline 0'], p, H))
    steps.append(('%s_shore' % p, ['ren_Shoreline 1'], p, H))
    steps.append(('%s_nosim' % p, ['ren_WaterSim 0'], p, H))
    steps.append(('%s_sim' % p, ['ren_WaterSim 1'], p, H))
for api in apis:
    name = 'steps_%s.lua' % tag
    with open(jobs.HERE + '/' + name, 'w') as o:
        o.write('AB_PRESETS = { %s }\nAB_STEPS = {\n' % pres)
        o.write("  { 'setup', { 'sc_FrameTimeClamp 0' }, 'fall', 3 },\n")
        for lab, cmds, p, hold in steps:
            o.write("  { %r, { %s }, %r, %d },\n" % (lab, ', '.join(repr(c) for c in cmds), p, hold))
        o.write('}\n')
    jobs.run(exe, api, '%s_%s' % (tag, api), 'river', name, prefs=cfg, con='sc_FrameTimeClamp=0')
