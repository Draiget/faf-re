"""frames_paused.py <label> <apis> <cfgs> [scenes]: paused frames of the exe named perf.exe, dumped to <out>/cmp_<label>_<cfg>_<scene>_<api>/
cfg: default | off (every option off, parity.OFF_OURS) | user. scenes: nuke,battle"""
import sys, os, shutil
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # tools/perf_audit
import jobs, parity
label = sys.argv[1]; apis = sys.argv[2].split(','); cfgs = sys.argv[3].split(',')
scenes = sys.argv[4].split(',') if len(sys.argv) > 4 else ['nuke', 'battle']
EX = {'nuke': ['-Tx', '150', '-Tz', '150', '-PauseAt', '42', '-Start', '14'], 'battle': ['-Tx', '73.5', '-Ty', '23', '-Tz', '388.5', '-PauseAt', '24', '-Start', '14']}
for scene in scenes:
    for api in apis:
        for cfg in cfgs:
            steps = 'steps_p2cmp.lua'
            with open(jobs.HERE + '/' + steps, 'w') as o:
                o.write("AB_PRESETS = { wide = { 60, 0.9, 0, 0, 0 }, close = { 25, 0.7, 0, 0, 0 } }\nAB_STEPS = {\n")
                cmds = parity.OFF_OURS if cfg == 'off' else ['sc_FrameTimeClamp 4']
                if cfg == 'off':
                    cmds = ['sc_FrameTimeClamp 4'] + [c for c in parity.OFF_OURS if not c.startswith('sc_FrameTimeClamp')]
                if cfg == 'lights':
                    cmds = ['sc_FrameTimeClamp 4', 'ren_DynLights 4', 'ren_ShadowFilter 0']
                o.write("  { 'setup', { %s }, 'wide', 6 },\n" % ', '.join(repr(c) for c in cmds))
                o.write("  { 'hold', {}, 'wide', 4 },\n  { 'close', {}, 'close', 5 },\n}\n")
            d = '%s/perf_out/cmp_%s_%s_%s_%s' % (jobs.S, label, cfg, scene, api)
            shutil.rmtree(d, ignore_errors=True)
            os.makedirs(d, exist_ok=True)
            con = ';'.join(c.replace(' ', '=') for c in cmds) if cfg == 'off' else ''
            jobs.run('perf', api, 'p2cmp_%s_%s_%s' % (label, cfg, scene), scene, steps, prefs='off' if cfg == 'off' else ('default' if cfg == 'lights' else cfg), env='FAF_GAL_DUMP_DIR=%s;FAF_GAL_DUMP_SECONDS=1' % d, extra=EX[scene], con=con)
