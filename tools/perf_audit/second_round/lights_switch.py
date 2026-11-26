"""lights_switch.py <tag> <reps> <exe-label>: 80 v 80 standing battle, lights off, switched on to Ultra in the running game, then held; per window times of the switch-on and the
passes of the held steps (LightsCollect ...). Runs the exe that is named perf.exe in the run folder; <exe-label> only names the logs."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # tools/perf_audit
import jobs
tag = sys.argv[1]; reps = int(sys.argv[2]); label = sys.argv[3]
env = sys.argv[4] if len(sys.argv) > 4 else ''
name = 'steps_%s.lua' % tag
with open(jobs.HERE + '/' + name, 'w') as o:
    o.write("AB_PRESETS = { wide = { 70, 0.95, 0, 0, 0 } }\nAB_STEPS = {\n")
    o.write("  { 'off', { 'sc_FrameTimeClamp 0', 'ren_DynLights 0' }, 'wide', 8 },\n")
    o.write("  { 'on', { 'ren_DynLights 4' }, 'wide', 10 },\n")
    o.write("  { 'held1', {}, 'wide', 10 },\n  { 'held2', {}, 'wide', 10 },\n")
    o.write("  { 'medium', { 'ren_DynLights 2' }, 'wide', 8 },\n")
    o.write("  { 'ultra_again', { 'ren_DynLights 4' }, 'wide', 8 },\n}\n")
for rep in range(reps):
    jobs.run('perf', 'd3d12', '%s_%s_r%d' % (tag, label, rep), 'battle', name, prefs='default', con='sc_FrameTimeClamp=0', env=env)
