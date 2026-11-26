"""jobs.py: generic job runner around perf_run.ps1 and the queue of the second phase (memory diff, nuke probe, feature tables).
usage: python jobs.py <queue> [--exe perf]   queue: mem | nuke | feat | soak | cold | hitch"""
import argparse, json, os, subprocess, sys, time
sys.path.insert(0, os.path.dirname(__file__))
import perf_parse as pp
LOGS = os.environ.get('FAF_LOGS', 'C:/ProgramData/FAForever/logs')
import feat_report as fr

S = S = os.environ.get('PERF_AUDIT_OUT', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'out')).replace(chr(92), '/')
HERE = os.path.dirname(os.path.abspath(__file__)).replace(chr(92), '/')
os.makedirs(S + '/perf_out', exist_ok=True)
LAKE = '/maps/adaptive_acid_lakes.v0004/adaptive_acid_lakes_scenario.lua'
RIVER = '/maps/faf_re_waterrivers/faf_re_waterrivers_scenario.lua'
PREFS = {'off': 'Game_perf_off.prefs', 'off_base': 'Game_perf_off_base.prefs', 'default': 'Game_perf_default.prefs', 'user': 'Game_perf_user.prefs'}
SCENES = {   # name -> (perf_run scene, map, count, interval, extra args)
    'lake': ('static', LAKE, 40, 500, ['-Tx', '73.5', '-Ty', '23', '-Tz', '372']),
    'battle': ('battlestill', LAKE, 80, 150, ['-Tx', '73.5', '-Ty', '23', '-Tz', '388.5']),
    'soakbattle': ('soak', LAKE, 100, 150, ['-Tx', '73.5', '-Ty', '23', '-Tz', '456']),
    'nuke': ('nuke', LAKE, 40, 150, ['-Tx', '150', '-Tz', '150', '-PauseAt', '42', '-Start', '14']),
    'river': ('falls', RIVER, 40, 300, ['-Tx', '130', '-Ty', '35', '-Tz', '76']),
    'strategic': ('battlestill', LAKE, 80, 150, ['-Tx', '73.5', '-Ty', '23', '-Tz', '388.5']),
}


def run(exe, api, tag, scene, steps, prefs='off', interval=None, hold=3, mem=0, env='', cache='default', con='', count=None, extra=None, ps='perf_run.ps1', timeout=1500, cachedir='', cacheclear=0, xargs=None):
    sc, mp, cnt, itv, ex = SCENES[scene]
    if scene == 'river':
        con = ('sim_FixWaterBodies=1;sim_FixRivers=1;' + con).rstrip(';')
    args = ['pwsh', '-NoProfile', '-File', HERE + '/' + ps, '-Exe', exe, '-Api', api, '-Tag', tag, '-Scene', sc, '-Steps', steps, '-Prefs', PREFS[prefs], '-Map', mp,
            '-Count', str(count or cnt), '-Interval', str(interval or itv), '-Hold', str(hold), '-Mem', str(mem), '-Cache', cache, '-QuietWait', '10', '-Timeout', str(timeout)] + (extra or ex)
    if xargs:
        args += ['-ExtraArgs'] + xargs
    if cachedir:
        args += ['-CacheDir', cachedir, '-CacheClear', str(cacheclear)]
    if env:
        args += ['-EnvExtra', env]
    if con:
        args += ['-ExtraCon', con]
    t0 = time.time()
    r = subprocess.run(args, capture_output=True, text=True)
    log = LOGS + '/pf_%s_%s_%s.log' % (tag, api, exe)
    print('%s %s %s %s %s: %s (%.0fs)' % (tag, exe, api, scene, prefs, r.stdout.strip().splitlines()[-1][:200] if r.stdout.strip() else r.stderr[-200:], time.time() - t0), flush=True)
    return log


def gen(scene, api, out, hold=3, reps=3, only=None):
    cmd = ['python', HERE + '/gen_steps.py', scene, api, HERE + '/' + out, str(hold), str(reps)] + (['only=' + ','.join(only)] if only else [])
    print(subprocess.run(cmd, capture_output=True, text=True).stdout.strip(), flush=True)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('queue')
    ap.add_argument('--apis', default='d3d12,vulkan,d3d11')
    ap.add_argument('--scenes', default='lake,battle,nuke,river,strategic')
    ap.add_argument('--exe', default='perf')
    ap.add_argument('--tag', default='ft')
    ap.add_argument('--hold', type=float, default=3)
    ap.add_argument('--reps', type=int, default=3)
    a = ap.parse_args()
    if a.queue == 'mem':
        for cfg in ('off', 'default', 'user'):
            for exe in ('perfbase', 'perf'):
                pref = 'off_base' if (cfg == 'off' and exe == 'perfbase') else cfg
                run(exe, 'd3d12', 'mem_%s' % cfg, 'lake', 'steps_mem.lua', prefs=pref, mem=1, env='FAF_GAL_MEMORY_LOG=2', hold=8, interval=500,
                    con='sc_FrameTimeClamp=0' if cfg != 'off' else '')
    elif a.queue == 'cmp':   # frames of a paused game with lights on, for a byte comparison of two builds: --exe names the label of the build under the name perf.exe
        for scene, ex in (('nuke', ['-Tx', '150', '-Tz', '150', '-PauseAt', '42', '-Start', '14']), ('battle', ['-Tx', '73.5', '-Ty', '23', '-Tz', '388.5', '-PauseAt', '24', '-Start', '14'])):
            for api in a.apis.split(','):
                steps = 'steps_cmp_%s.lua' % scene
                with open(HERE + '/' + steps, 'w') as o:
                    o.write("AB_PRESETS = { wide = { 60, 0.9, 0, 0, 0 }, close = { 25, 0.7, 0, 0, 0 } }" + chr(10) + "AB_STEPS = {" + chr(10))
                    o.write("  { 'lights', { 'sc_FrameTimeClamp 4', 'ren_DynLights 4', 'ren_ShadowFilter 0' }, 'wide', 6 }," + chr(10))
                    o.write("  { 'hold', {}, 'wide', 4 }," + chr(10))
                    o.write("  { 'close', {}, 'close', 5 }," + chr(10) + "}" + chr(10))
                d = '%s/perf_out/cmp_%s_%s_%s' % (S, a.exe, scene, api)
                import shutil
                shutil.rmtree(d, ignore_errors=True)
                os.makedirs(d, exist_ok=True)
                run('perf', api, 'cmp_%s_%s' % (a.exe, scene), scene, steps, prefs='default', env='FAF_GAL_DUMP_DIR=%s;FAF_GAL_DUMP_SECONDS=1' % d, extra=ex)
    elif a.queue == 'partdiag':   # which part of the patched particle.fx costs while every particle feature is off (diagnostic build): FAF_PARTICLE_PATCH_DIAG bits
        import parity
        pres = "wide = { 70, 0.95, 0, 0, 0 }, strat = { 420, 1.25, 0, 0, 0 }"
        for rep in range(2):
            for lab, exe, env, xa in (('base', 'perfbase', '', None), ('d0', 'perf', '', None), ('d1', 'perf', 'FAF_PARTICLE_PATCH_DIAG=1', None), ('d2', 'perf', 'FAF_PARTICLE_PATCH_DIAG=2', None),
                                      ('d4', 'perf', 'FAF_PARTICLE_PATCH_DIAG=4', None), ('d7', 'perf', 'FAF_PARTICLE_PATCH_DIAG=7', None), ('unp', 'perf', '', ['/noparticlelowres'])):
                cmds = parity.OFF_BASE if exe == 'perfbase' else parity.OFF_OURS
                steps = 'steps_partdiag_%s.lua' % lab
                parity.write_steps(HERE + '/' + steps, pres, 'wide', 'strat', cmds, 10)
                run(exe, 'd3d12', 'pd_%s_r%d' % (lab, rep), 'battle', steps, prefs='off_base' if exe == 'perfbase' else 'off', con=';'.join(c.replace(' ', '=') for c in cmds), xargs=xa, env=env)
    elif a.queue == 'partest':   # does the patched particle.fx cost something while every particle feature is off? perf, perf with /noparticlelowres (unpatched), baseline
        import parity
        pres = "wide = { 70, 0.95, 0, 0, 0 }, strat = { 420, 1.25, 0, 0, 0 }"
        for rep in range(3):
            for exe, xa, lab in (('perfbase', None, 'base'), ('perf', None, 'patched'), ('perf', ['/noparticlelowres'], 'unpatched')):
                cmds = parity.OFF_BASE if exe == 'perfbase' else parity.OFF_OURS
                steps = 'steps_partest_%s.lua' % lab
                parity.write_steps(HERE + '/' + steps, pres, 'wide', 'strat', cmds, 10)
                run(exe, 'd3d12', 'partest_%s_r%d' % (lab, rep), 'battle', steps, prefs='off_base' if exe == 'perfbase' else 'off', con=';'.join(c.replace(' ', '=') for c in cmds), xargs=xa)
    elif a.queue == 'after':   # the same probes against the fixed build: particles, lights and water CPU, tagged af
        for scene, only, tag in (('battle', ['lowres', 'softp'], 'afpart'), ('battle', ['lights'], 'aflights'), ('river', ['watersim', 'waterfalls'], 'afriver'), ('battle', ['watersim'], 'afwaterb')):
            steps = 'steps_%s_%s_d3d12.lua' % (tag, scene)
            gen(scene, 'd3d12', steps, 4, 3, only=only)
            run(a.exe, 'd3d12', '%s_%s' % (tag, scene), scene, steps, prefs='default', con='sc_FrameTimeClamp=0')
    elif a.queue == 'nukepart':   # the particle estimate: Half against Full (and soft particles) at 1600x900 on the nuke and the battle
        for scene in ('nuke', 'battle'):
            steps = 'steps_%s_%s_d3d12.lua' % (a.tag, scene)
            gen(scene, 'd3d12', steps, 4, 3, only=['lowres', 'softp'])
            run(a.exe, 'd3d12', '%s_%s' % (a.tag, scene), scene, steps, prefs='default', con='sc_FrameTimeClamp=0')
    elif a.queue == 'load':   # cold and warm shader caches per API, both exes: the time to the first frame and to the end of the background compiles
        for api in a.apis.split(','):
            for exe in ('perfbase', 'perf'):
                cd = '%s/perf_out/cache_load_%s_%s' % (S, exe, api)
                run(exe, api, 'load_cold', 'lake', 'steps_mem.lua', prefs='default', hold=8, interval=500, cachedir=cd, cacheclear=1, timeout=1500, con='sc_FrameTimeClamp=0')
                run(exe, api, 'load_warm', 'lake', 'steps_mem.lua', prefs='default', hold=8, interval=500, cachedir=cd, cacheclear=0, timeout=600, con='sc_FrameTimeClamp=0')
    elif a.queue == 'd3dcache':   # does the baseline's Direct3D 11 effect cache hit on a second launch? (own cache folder, one cold and two warm launches)
        cd = '%s/perf_out/cache_chk_perfbase_d3d11' % S
        run('perfbase', 'd3d11', 'chk_cold', 'lake', 'steps_mem.lua', prefs='default', hold=3, interval=500, cachedir=cd, cacheclear=1, timeout=900, con='sc_FrameTimeClamp=0')
        run('perfbase', 'd3d11', 'chk_warm1', 'lake', 'steps_mem.lua', prefs='default', hold=3, interval=500, cachedir=cd, cacheclear=0, timeout=900, con='sc_FrameTimeClamp=0')
        run('perfbase', 'd3d11', 'chk_warm2', 'lake', 'steps_mem.lua', prefs='default', hold=3, interval=500, cachedir=cd, cacheclear=0, timeout=900, con='sc_FrameTimeClamp=0')
    elif a.queue == 'mbfinal':   # the settled memory of the default configuration with the final exe (compare with membisect 'ours')
        run(a.exe, 'd3d12', 'mb_final', 'lake', 'steps_mem.lua', prefs='default', mem=1, env='FAF_GAL_MEMORY_LOG=2', hold=8, interval=500, con='sc_FrameTimeClamp=0')
    elif a.queue == 'umb':   # where the video memory of the user's profile goes: the profile with one group of its options at the default (mk_prefs_umb.py makes the prefs)
        for lab in ('all', 'nolights', 'noshadow', 'noao', 'nosoft', 'nosharp', 'less3'):
            PREFS['u_' + lab] = 'Game_perf_u_%s.prefs' % lab if lab != 'all' else PREFS['user']
            run(a.exe, 'd3d12', 'umb2_%s' % lab, 'lake', 'steps_mem.lua', prefs='u_' + lab, mem=1, env='FAF_GAL_MEMORY_LOG=2', hold=8, interval=500, con='sc_FrameTimeClamp=0')
    elif a.queue == 'vram':   # one session, features switched on one after the other, the process's GPU and private memory read after each (2 s samples)
        import gen_steps_cmds as g
        for api in ('d3d12', 'vulkan'):
            steps = 'steps_vram_%s.lua' % api
            lst = g.vram_steps(api)
            with open(HERE + '/' + steps, 'w') as o:
                o.write("AB_PRESETS = { lake = { 60, 0.9, 0, -25, 0 }, close = { 25, 0.7, 0, -10, 20 } }" + chr(10) + "AB_STEPS = {" + chr(10))
                for lab, cmds in lst:
                    o.write("  { %s, { %s }, %s, 7 }," % (repr(lab), ', '.join(repr(c) for c in cmds), repr('lake')) + chr(10))
                o.write("}" + chr(10))
            run('perf', api, 'vram', 'lake', steps, prefs='default', mem=1, hold=7, interval=500, timeout=900, con='sc_FrameTimeClamp=0')
    elif a.queue == 'vramiso':   # the memory of the three big post features in another order than 'vram': atmosphere alone first, then temporal AA, then the render scale
        import gen_steps_cmds as g
        for api in ('d3d12', 'vulkan'):
            steps = 'steps_vramiso_%s.lua' % api
            lst = g.vram_steps(api)[:3] + [('atmosphere', ['ren_Atmosphere 1']), ('taa', ['ren_Taa 1']), ('renderscale_75', ['ren_RenderScale 0.75']), ('final_hold', [])]
            with open(HERE + '/' + steps, 'w') as o:
                o.write("AB_PRESETS = { lake = { 60, 0.9, 0, -25, 0 } }" + chr(10) + "AB_STEPS = {" + chr(10))
                for lab, cmds in lst:
                    o.write("  { %s, { %s }, %s, 7 }," % (repr(lab), ', '.join(repr(c) for c in cmds), repr('lake')) + chr(10))
                o.write("}" + chr(10))
            run('perf', api, 'vramiso', 'lake', steps, prefs='default', mem=1, hold=7, interval=500, timeout=900, con='sc_FrameTimeClamp=0')
    elif a.queue == 'toggle':   # the hitch of switching each feature on and off in a running game (windows of 30 frames, the largest frame of each step)
        tg = [('lights', 'ren_DynLights 4', 'ren_DynLights 0'), ('shadowfilter', 'ren_ShadowFilter 4', 'ren_ShadowFilter 0'), ('waterq', 'ren_WaterQuality 3', 'ren_WaterQuality 0'), ('taa', 'ren_Taa 1', 'ren_Taa 0'),
              ('rscale', 'ren_RenderScale 0.75', 'ren_RenderScale 1'), ('ao', 'ren_AmbientOcclusion 4', 'ren_AmbientOcclusion 0'), ('atmosphere', 'ren_Atmosphere 1', 'ren_Atmosphere 0'),
              ('softp', 'ren_SoftParticles 2', 'ren_SoftParticles 0'), ('lowres', 'ren_ParticleLowRes 1', 'ren_ParticleLowRes 0'), ('rays', 'ren_RayTracedShadows 1', 'ren_RayTracedShadows 0'),
              ('watersim', 'ren_WaterSim 1', 'ren_WaterSim 0'), ('aa', 'ren_Fxaa 2', 'ren_Fxaa 0')]
        for api in ('d3d12', 'vulkan', 'd3d11'):
            steps = 'steps_toggle_%s.lua' % api
            with open(HERE + '/' + steps, 'w') as o:
                o.write("AB_PRESETS = { lake = { 60, 0.9, 0, -25, 0 } }" + chr(10) + "AB_STEPS = {" + chr(10))
                o.write("  { 'setup', { 'sc_FrameTimeClamp 0', 'ren_DynLights 0', 'ren_ShadowFilter 0', 'ren_AmbientOcclusion 0', 'ren_Fxaa 0' }, 'lake', 4 }," + chr(10))
                for name, on, off in tg:
                    if api == 'd3d11' and name in ('taa', 'atmosphere', 'rays'):
                        continue
                    h = 45 if (api == 'd3d11' and name in ('lights', 'shadowfilter')) else 4
                    o.write("  { 'tg_%s_on', { '%s' }, 'lake', %d }," % (name, on, h) + chr(10))
                    o.write("  { 'tg_%s_off', { '%s' }, 'lake', 4 }," % (name, off) + chr(10))
                o.write("}" + chr(10))
            run('perf', api, 'toggle', 'lake', steps, prefs='default', hold=4, interval=30, timeout=900, con='sc_FrameTimeClamp=0')
    elif a.queue == 'membisect':   # where do the +58 MB of the all-off build come from: startup switches against the memory of a settled lake scene
        runs = [('perfbase', 'base', '', None), ('perf', 'ours', '', None), ('perf', 'noadd', '', None), ('perf', 'nolowres', '', ['/noparticlelowres']),
                ('perf', 'sim0', 'ren_WaterSim=0', None), ('perf', 'water0', 'ren_WaterSim=0;ren_WaterQuality=0;ren_WaterSSR=0;ren_WaterAbsorb=0;ren_WaterBanks=0;ren_River=0;ren_TerrainWaterLevels=0;ren_ShoreTessCoeff=0', ['/noparticlelowres']),
                ('perf', 'lowres0', 'ren_ParticleLowRes=0;ren_SoftParticles=0', None), ('perf', 'aa0', 'ren_Fxaa=0;ren_Sharpen=0;ren_Grade=0;ren_AmbientOcclusion=0', None)]
        for exe, lab, con, xa in runs:
            env = 'FAF_GAL_MEMORY_LOG=2' + (';FAF_NO_RENDER_ADDITIONS=1' if lab == 'noadd' else '')
            run(exe, 'd3d12', 'mb_%s' % lab, 'lake', 'steps_mem.lua', prefs='default', mem=1, env=env, hold=8, interval=500, con=('sc_FrameTimeClamp=0;' + con).rstrip(';'), xargs=xa)
    elif a.queue == 'soak':   # 4-minute battle, ren_Info every 15 s, memory samples every 2 s; ultra twice for the leak comparison
        plan = [('perf', 'd3d12', 'ultra', 'default', 'u1'), ('perf', 'd3d12', 'ultra', 'default', 'u2'), ('perf', 'd3d12', 'user', 'user', 'user'), ('perfbase', 'd3d12', 'base', 'default', 'base'),
                ('perf', 'vulkan', 'ultra', 'default', 'u1')]
        for exe, api, cfg, prefs, label in plan:
            steps = 'steps_soak_%s_%s.lua' % (cfg, api)
            print(subprocess.run(['python', HERE + '/gen_soak.py', api, cfg, HERE + '/' + steps, '16'], capture_output=True, text=True).stdout.strip(), flush=True)
            run(exe, api, 'soak_%s' % label, 'soakbattle', steps, prefs=prefs, mem=1, env='FAF_GAL_MEMORY_LOG=15', hold=15, interval=60, timeout=900, con='sc_FrameTimeClamp=0')
    elif a.queue == 'feat':
        for api in a.apis.split(','):
            for scene in a.scenes.split(','):
                if (api == 'd3d11' and scene not in ('lake',)) or (api == 'vulkan' and scene == 'nuke'):
                    continue   # time: the Direct3D 11 table covers the lake, the Vulkan ones the lake, the battle and the river
                steps = 'steps_%s_%s_%s.lua' % (a.tag, scene, api)
                gen(scene if scene != 'strategic' else 'strategic', api, steps, a.hold, a.reps)
                # the shipped defaults at startup (effects built as a player gets them); the setup step of the steps file then turns every feature off live
                run(a.exe, api, '%s_%s' % (a.tag, scene), scene, steps, prefs='default', con='sc_FrameTimeClamp=0')
