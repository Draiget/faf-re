"""parity.py: runs the parity matrix (exe x cfg x api x scene x rep, alternating order) and appends one JSON record per run to perf_out/parity.jsonl.
usage: python parity.py [--apis d3d12,d3d11,vulkan] [--scenes lake,battle,river] [--reps 3] [--cfgs off,default,user] [--tag par]"""
import argparse, json, os, re, subprocess, sys, time
sys.path.insert(0, os.path.dirname(__file__))
import perf_parse as pp
LOGS = os.environ.get('FAF_LOGS', 'C:/ProgramData/FAForever/logs')

S = S = os.environ.get('PERF_AUDIT_OUT', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'out')).replace(chr(92), '/')
HERE = os.path.dirname(os.path.abspath(__file__)).replace(chr(92), '/')
os.makedirs(S + '/perf_out', exist_ok=True)
OFF_OURS = ['sc_FrameTimeClamp 0', 'ren_MaxFps 0', 'ren_FpsLimit 0', 'ren_DynLights 0', 'ren_ShadowFilter 0', 'ren_AmbientOcclusion 0', 'ren_Fxaa 0', 'ren_Sharpen 0', 'ren_Grade 0', 'ren_Taa 0',
            'ren_RenderScale 1', 'ren_SoftParticles 0', 'ren_ParticleLowRes 0', 'ren_WaterQuality 0', 'ren_WaterSSR 0', 'ren_WaterCaustics 0', 'ren_WaterAbsorb 0', 'ren_WaterSheen 0',
            'ren_WaterUnitShadows 0', 'ren_WaterBanks 0', 'ren_River 0', 'ren_Waterfalls 0', 'ren_TerrainWaterLevels 0', 'ren_DynLightsWaterLevels 0', 'ren_ShoreTessCoeff 0', 'ren_WaterSim 0',
            'ren_Atmosphere 0', 'ren_BloomWide 0', 'ren_RayTracedShadows 0', 'ren_ShadowCascades 3', 'ren_TextureAnisotropy 8']
# the shared cvars at the same value; upstream's own AO is ren_Ao; its water has no switches
OFF_BASE = ['sc_FrameTimeClamp 0', 'ren_Ao 0', 'ren_Fxaa 0', 'ren_Sharpen 0', 'ren_Grade 0', 'ren_Taa 0', 'ren_RenderScale 1', 'ren_Atmosphere 0', 'ren_BloomWide 0',
            'ren_RayTracedShadows 0', 'ren_ShadowCascades 3', 'ren_TextureAnisotropy 8']
DEFAULT = ['sc_FrameTimeClamp 0']
SCENES = {   # scene key -> (perf_run scene, map, count, presets, first, second, interval, extra con)
    'lake': ('static', '/maps/adaptive_acid_lakes.v0004/adaptive_acid_lakes_scenario.lua', 40, "lake = { 60, 0.9, 0, -25, 0 }, close = { 25, 0.7, 0, -10, 20 }", 'lake', 'close', 500, ''),
    'battle': ('soak', '/maps/adaptive_acid_lakes.v0004/adaptive_acid_lakes_scenario.lua', 100, "wide = { 70, 0.95, 0, 0, 0 }, strat = { 420, 1.25, 0, 0, 0 }", 'wide', 'strat', 150, ''),
    'river': ('falls', '/maps/faf_re_waterrivers/faf_re_waterrivers_scenario.lua', 40, "fall = { 38, 0.45, 3.14, 0, 0, 0 }, wide = { 90, 0.8, 3.14, 0, 0, 0 }", 'fall', 'wide', 300,
              'sim_FixWaterBodies=1;sim_FixRivers=1'),
}
TXYZ = {'river': (130, 35, 76), 'lake': (73.5, 23, 372), 'battle': (73.5, 23, 456)}


def write_steps(path, presets, p1, p2, cmds, hold):
    q = lambda s: "'" + s + "'"
    with open(path, 'w') as o:
        o.write('AB_PRESETS = { %s }\nAB_STEPS = {\n' % presets)
        o.write("  { 'setup', { %s }, '%s', 3 },\n" % (', '.join(q(c) for c in cmds), p1))
        o.write("  { 'meas1', {}, '%s', %d },\n" % (p1, hold))
        o.write("  { 'meas2', {}, '%s', %d, 'info' },\n" % (p2, hold))
        o.write('}\n')


def run(exe, cfg, api, scene, rep, tag, hold=10):
    sc, mp, cnt, presets, p1, p2, interval, con = SCENES[scene]
    cmds = OFF_OURS if (cfg == 'off' and exe == 'perf') else OFF_BASE if (cfg == 'off') else DEFAULT
    if cfg == 'off' and exe == 'perfbase' and scene == 'river':
        cmds = OFF_BASE
    steps = 'steps_par_%s_%s_%s.lua' % (exe, cfg, scene)
    write_steps(HERE + '/' + steps, presets, p1, p2, cmds, hold)
    prefs = {'off': 'Game_perf_off.prefs' if exe == 'perf' else 'Game_perf_off_base.prefs', 'default': 'Game_perf_default.prefs', 'user': 'Game_perf_user.prefs'}[cfg]
    tx, ty, tz = TXYZ.get(scene, (0, 0, 0))
    t = '%s_%s_%s_%s_%s_r%d' % (tag, cfg, scene, exe, api, rep)
    args = ['pwsh', '-NoProfile', '-File', HERE + '/perf_run.ps1', '-Exe', exe, '-Api', api, '-Tag', t, '-Scene', sc, '-Steps', steps, '-Prefs', prefs, '-Map', mp, '-Count', str(cnt),
            '-Interval', str(interval), '-Hold', '3', '-Tx', str(tx), '-Ty', str(ty), '-Tz', str(tz), '-QuietWait', '10']
    startup = ';'.join(c.replace(' ', '=') for c in cmds) if cfg != 'default' else 'sc_FrameTimeClamp=0'
    con = (con + ';' if con else '') + startup
    args += ['-ExtraCon', con]
    r = subprocess.run(args, capture_output=True, text=True)
    log = LOGS + '/pf_%s_%s_%s.log' % (t, api, exe)
    # the tag in the log name is "<tag>_<api>_<exe>": perf_run builds it from -Tag, so the tag above carries the api again; read both spellings
    jf = '%s/perf_out/%s_%s_%s.json' % (S, t, api, exe)
    rec = {'exe': exe, 'cfg': cfg, 'api': api, 'scene': scene, 'rep': rep, 'tag': t, 'stdout': r.stdout.strip()[-400:]}
    try:
        rec.update(json.load(open(jf)))
        steps_, pre = pp.parse(log)
        byl = pp.by_label(steps_, skip=2)
        for lab in ('meas1', 'meas2'):
            if lab in byl:
                rec[lab] = {k: v for k, v in byl[lab][0].items()}
        txt = open(log, errors='replace').read()
        m = re.findall(r'process: ([\d.]+) MB private, ([\d.]+) MB working set \(peak ([\d.]+)', txt)
        if m:
            rec['proc_private_mb'] = float(m[-1][0]); rec['proc_ws_mb'] = float(m[-1][1]); rec['proc_peak_mb'] = float(m[-1][2])
        m = re.findall(r'budget: local ([\d.]+) / ([\d.]+) MB used, non-local ([\d.]+)', txt)
        if m:
            rec['gpu_local_mb'] = float(m[-1][0])
        m = re.findall(r'engine heap: ([\d.]+) MB in use', txt)
        if m:
            rec['heap_mb'] = float(m[-1])
        rec['errors'] = len(re.findall(r'^(error|warning: .*(shader|Shader|failed))', txt, re.M))
    except Exception as e:
        rec['err'] = repr(e)
    with open(S + '/perf_out/%s.jsonl' % tag, 'a') as f:
        f.write(json.dumps(rec) + '\n')
    return rec


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--apis', default='d3d12,d3d11,vulkan')
    ap.add_argument('--scenes', default='lake,battle,river')
    ap.add_argument('--reps', default='3')
    ap.add_argument('--cfgs', default='off,default')
    ap.add_argument('--tag', default='par')
    ap.add_argument('--exes', default='perfbase,perf')
    a = ap.parse_args()
    reps = {api: int(r) for api, r in zip(a.apis.split(','), (a.reps.split(',') * 3)[:len(a.apis.split(','))])} if ',' in a.reps else {api: int(a.reps) for api in a.apis.split(',')}
    for api in a.apis.split(','):
        for rep in range(reps[api]):
            for scene in a.scenes.split(','):
                for cfg in a.cfgs.split(','):
                    order = [e for e in (['perfbase', 'perf'] if (rep % 2 == 0) else ['perf', 'perfbase']) if e in a.exes.split(',')]
                    for exe in order:
                        t0 = time.time()
                        rec = run(exe, cfg, api, scene, rep, a.tag)
                        g = lambda k, f: rec.get(k, {}).get(f, float('nan'))
                        print('%s %s %s %s r%d: state %s gpu %.3f cpu %.3f wall %.3f p99 %.2f ws %s (%.0fs)' % (exe, cfg, api, scene, rep, rec.get('state'), g('meas1', 'gpu'), g('meas1', 'cpu'), g('meas1', 'wall'), g('meas1', 'p99'), rec.get('proc_private_mb'), time.time() - t0), flush=True)
