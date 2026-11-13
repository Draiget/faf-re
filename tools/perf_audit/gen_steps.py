"""gen_steps.py <scene> <api> <out.lua> [hold] [reps] [only=feat1,feat2]  -> steps file for perf_run.ps1
Scenes: lake (static scene), battle (soak scene), nuke (paused explosion), river (falls map), strategic."""
import sys
scene, api, out = sys.argv[1], sys.argv[2], sys.argv[3]
hold = float(sys.argv[4]) if len(sys.argv) > 4 else 3
reps = int(sys.argv[5]) if len(sys.argv) > 5 else 3
only = None
for a in sys.argv[6:]:
    if a.startswith('only='):
        only = set(a[5:].split(','))
RT = api in ('d3d12', 'vulkan')
PRESETS = {
    'lake': "lake = { 60, 0.9, 0, -25, 0 }, close = { 25, 0.7, 0, -10, 20 }",
    'battle': "wide = { 70, 0.95, 0, 0, 0 }, close = { 22, 0.6, 0, 0, 0 }",
    'nuke': "wide = { 60, 0.9, 0, 0, 0 }",
    'river': "fall = { 38, 0.45, 3.14, 0, 0, 0 }, wide = { 90, 0.8, 3.14, 0, 0, 0 }",
    'strategic': "strat = { 420, 1.25, 0, 0, 0 }",
}
PRESET = {'lake': 'lake', 'battle': 'wide', 'nuke': 'wide', 'river': 'fall', 'strategic': 'strat'}[scene]
# every feature of ours at its off value, plus the shared ones at the same value as the baseline build
OFF = ['sc_FrameTimeClamp 0', 'ren_MaxFps 0', 'ren_FpsLimit 0', 'ren_DynLights 0', 'ren_ShadowFilter 0', 'ren_AmbientOcclusion 0', 'ren_Fxaa 0', 'ren_Sharpen 0',
       'ren_Grade 0', 'ren_Taa 0', 'ren_RenderScale 1', 'ren_SoftParticles 0', 'ren_ParticleLowRes 0', 'ren_WaterQuality 0', 'ren_WaterSSR 0', 'ren_WaterCaustics 0',
       'ren_WaterAbsorb 0', 'ren_WaterSheen 0', 'ren_WaterUnitShadows 0', 'ren_WaterBanks 0', 'ren_River 0', 'ren_Waterfalls 0', 'ren_TerrainWaterLevels 0',
       'ren_DynLightsWaterLevels 0', 'ren_ShoreTessCoeff 0', 'ren_Atmosphere 0', 'ren_BloomWide 0', 'ren_RayTracedShadows 0', 'ren_RayAo 0', 'ren_RayBounce 0',
       'ren_RayWaterReflections 0', 'ren_RaySunAngle 0', 'ren_ShadowCascades 3', 'ren_TextureAnisotropy 8']
OFF.append('ren_WaterSim 0')   # live: the shader patch stays, the simulation and its binding stop
S_ALL = {'lake', 'battle', 'nuke', 'river', 'strategic'}
F = []


def feat(name, off, levels, scenes=S_ALL, apis=('d3d11', 'd3d12', 'vulkan')):
    F.append(dict(name=name, off=off, levels=levels, scenes=scenes, apis=apis))


LIGHT_RESET = ['ren_DynLightsMode 1', 'ren_DynLightsShadows 1', 'ren_DynLightsFieldShadows 1', 'ren_DynLightsSunShadows 1', 'ren_DynLights 0']
feat('lights', ['ren_DynLights 0'], [('Low', ['ren_DynLights 1']), ('Medium', ['ren_DynLights 2']), ('High', ['ren_DynLights 3']), ('Ultra', ['ren_DynLights 4'])], {'lake', 'battle', 'nuke', 'strategic'}, ('d3d12', 'vulkan'))
feat('lightsU', LIGHT_RESET, [('grid', ['ren_DynLights 4', 'ren_DynLightsMode 0']), ('field_noshadow', ['ren_DynLights 4', 'ren_DynLightsMode 1', 'ren_DynLightsShadows 0', 'ren_DynLightsFieldShadows 0', 'ren_DynLightsSunShadows 0']), ('field', ['ren_DynLights 4', 'ren_DynLightsMode 1', 'ren_DynLightsShadows 1', 'ren_DynLightsFieldShadows 1', 'ren_DynLightsSunShadows 1'])], {'lake', 'battle', 'nuke'}, ('d3d12', 'vulkan'))
feat('shadowfilter', ['ren_ShadowFilter 0'], [('Low', ['ren_ShadowFilter 1']), ('Medium', ['ren_ShadowFilter 2']), ('High', ['ren_ShadowFilter 3']), ('Ultra', ['ren_ShadowFilter 4'])], {'lake', 'battle', 'nuke', 'strategic'})
feat('cascades', ['ren_ShadowCascades 3'], [('c1', ['ren_ShadowCascades 1']), ('c2', ['ren_ShadowCascades 2'])], {'lake', 'battle', 'nuke'}, ('d3d12', 'vulkan'))
feat('ao', ['ren_AmbientOcclusion 0'], [('Standard', ['ren_AmbientOcclusion 1']), ('Low', ['ren_AmbientOcclusion 2']), ('Medium', ['ren_AmbientOcclusion 3']), ('High', ['ren_AmbientOcclusion 4'])], {'lake', 'battle', 'nuke', 'strategic'})
feat('aa', ['ren_Fxaa 0'], [('FXAA', ['ren_Fxaa 1']), ('SMAA', ['ren_Fxaa 2'])], {'lake', 'battle', 'nuke', 'strategic'})
feat('sharpen', ['ren_Sharpen 0'], [('Low', ['ren_Sharpen 0.25']), ('Medium', ['ren_Sharpen 0.5']), ('High', ['ren_Sharpen 1'])], {'lake', 'battle'})
feat('grade', ['ren_Grade 0'], [('On', ['ren_Grade 1'])], {'lake', 'battle'})
feat('aastack', ['ren_Fxaa 0', 'ren_Sharpen 0', 'ren_Grade 0'], [('fxaa+sharp+grade', ['ren_Fxaa 1', 'ren_Sharpen 0.5', 'ren_Grade 1']), ('smaa+sharp+grade', ['ren_Fxaa 2', 'ren_Sharpen 1', 'ren_Grade 1'])], {'lake', 'battle', 'strategic'})
feat('taa', ['ren_Taa 0'], [('On', ['ren_Taa 1'])], {'lake', 'battle'}, ('d3d12', 'vulkan'))
feat('rscale', ['ren_RenderScale 1'], [('85', ['ren_RenderScale 0.85']), ('75', ['ren_RenderScale 0.75']), ('50', ['ren_RenderScale 0.5'])], {'lake', 'battle'})
feat('softp', ['ren_SoftParticles 0'], [('Low', ['ren_SoftParticles 1']), ('High', ['ren_SoftParticles 2'])], {'lake', 'battle', 'nuke'})
feat('lowres', ['ren_ParticleLowRes 0'], [('Half', ['ren_ParticleLowRes 1']), ('Quarter', ['ren_ParticleLowRes 2'])], {'battle', 'nuke'})
feat('bloomwide', ['ren_BloomWide 0'], [('Normal', ['ren_BloomWide 1']), ('Strong', ['ren_BloomWide 2'])], {'lake', 'nuke'}, ('d3d12', 'vulkan'))
feat('atmosphere', ['ren_Atmosphere 0'], [('On', ['ren_Atmosphere 1'])], {'lake', 'battle', 'river'}, ('d3d12', 'vulkan'))
feat('aniso', ['ren_TextureAnisotropy 8'], [('tri', ['ren_TextureAnisotropy 0']), ('x16', ['ren_TextureAnisotropy 16'])], {'lake', 'battle'})
feat('waterq', ['ren_WaterQuality 0'], [('1', ['ren_WaterQuality 1']), ('2', ['ren_WaterQuality 2']), ('3', ['ren_WaterQuality 3'])], {'lake', 'river'})
feat('watersim', ['ren_WaterSim 0'], [('On', ['ren_WaterSim 1'])], {'lake', 'river', 'battle'})
feat('ssr', ['ren_WaterSSR 0'], [('On', ['ren_WaterSSR 1'])], {'lake', 'river'})
feat('caustics', ['ren_WaterCaustics 0'], [('50', ['ren_WaterCaustics 50']), ('100', ['ren_WaterCaustics 100'])], {'lake', 'river'})
feat('absorb', ['ren_WaterAbsorb 0'], [('On', ['ren_WaterAbsorb 1'])], {'lake', 'river'})
feat('sheen', ['ren_WaterSheen 0'], [('On', ['ren_WaterSheen 55'])], {'lake', 'river'})
feat('unitshadows', ['ren_WaterUnitShadows 0'], [('On', ['ren_WaterUnitShadows 45'])], {'lake', 'river'})
feat('banks', ['ren_WaterBanks 0'], [('1', ['ren_WaterBanks 1']), ('2', ['ren_WaterBanks 2'])], {'lake', 'river'})
feat('river', ['ren_River 0'], [('On', ['ren_River 1'])], {'river'})
feat('terrainwl', ['ren_TerrainWaterLevels 0'], [('On', ['ren_TerrainWaterLevels 1'])], {'lake', 'river'})
feat('shoretess', ['ren_ShoreTessCoeff 0'], [('On', ['ren_ShoreTessCoeff 0.1'])], {'lake', 'river'}, ('d3d12', 'vulkan'))
feat('waterfalls', ['ren_Waterfalls 0'], [('1', ['ren_Waterfalls 1']), ('2', ['ren_Waterfalls 2']), ('3', ['ren_Waterfalls 3'])], {'river'})
WATER_OFF = ['ren_WaterQuality 0', 'ren_WaterSSR 0', 'ren_WaterCaustics 0', 'ren_WaterAbsorb 0', 'ren_WaterSheen 0', 'ren_WaterUnitShadows 0', 'ren_WaterBanks 0', 'ren_River 0', 'ren_Waterfalls 0', 'ren_TerrainWaterLevels 0', 'ren_ShoreTessCoeff 0']
feat('waterall', WATER_OFF, [
    ('defaults', ['ren_WaterQuality 1', 'ren_WaterSSR 1', 'ren_WaterCaustics 50', 'ren_WaterAbsorb 1', 'ren_WaterSheen 55', 'ren_WaterUnitShadows 45', 'ren_WaterBanks 2', 'ren_River 1', 'ren_Waterfalls 2', 'ren_TerrainWaterLevels 1', 'ren_ShoreTessCoeff 0.1']),
    ('maxed', ['ren_WaterQuality 3', 'ren_WaterSSR 1', 'ren_WaterCaustics 100', 'ren_WaterAbsorb 1', 'ren_WaterSheen 55', 'ren_WaterUnitShadows 45', 'ren_WaterBanks 2', 'ren_River 1', 'ren_Waterfalls 3', 'ren_TerrainWaterLevels 1', 'ren_ShoreTessCoeff 0.1'])], {'lake', 'river'})
RAYS = [('shadows', ['ren_RayTracedShadows 1']), ('ao', ['ren_RayAo 1']), ('bounce', ['ren_RayBounce 1']), ('water', ['ren_RayWaterReflections 1']), ('soft', ['ren_RaySunAngle 3'])]
feat('rays', ['ren_RayTracedShadows 0', 'ren_RayAo 0', 'ren_RayBounce 0', 'ren_RayWaterReflections 0', 'ren_RaySunAngle 0'], RAYS, {'lake', 'battle'}, ('d3d12', 'vulkan'))
DEFAULT_ON = ['ren_Fxaa 1', 'ren_Sharpen 0.5', 'ren_Grade 1', 'ren_AmbientOcclusion 1', 'ren_ParticleLowRes 1', 'ren_SoftParticles 1', 'ren_WaterQuality 1', 'ren_WaterSSR 1', 'ren_WaterCaustics 50',
              'ren_WaterAbsorb 1', 'ren_WaterSheen 55', 'ren_WaterUnitShadows 45', 'ren_WaterBanks 2', 'ren_River 1', 'ren_Waterfalls 2', 'ren_TerrainWaterLevels 1', 'ren_ShoreTessCoeff 0.1', 'ren_DynLightsWaterLevels 1']
ULTRA = ['ren_DynLights 4', 'ren_ShadowFilter 4', 'ren_AmbientOcclusion 4', 'ren_Fxaa 2', 'ren_Sharpen 1', 'ren_Grade 1', 'ren_SoftParticles 2', 'ren_ParticleLowRes 1', 'ren_WaterQuality 3', 'ren_WaterSSR 1',
         'ren_WaterCaustics 100', 'ren_WaterAbsorb 1', 'ren_WaterSheen 55', 'ren_WaterUnitShadows 45', 'ren_WaterBanks 2', 'ren_River 1', 'ren_Waterfalls 3', 'ren_TerrainWaterLevels 1', 'ren_ShoreTessCoeff 0.1',
         'ren_DynLightsWaterLevels 1', 'ren_BloomWide 2']
if RT:
    ULTRA += ['ren_Taa 1', 'ren_Atmosphere 1']
ULTRA_RT = ['ren_RayTracedShadows 1', 'ren_RayAo 1', 'ren_RayBounce 1', 'ren_RayWaterReflections 1', 'ren_RaySunAngle 3']
if api == 'd3d11':
    ULTRA = [c for c in ULTRA if not c.startswith('ren_DynLights ') and 'BloomWide' not in c]
steps = []


def step(label, cmds, hold_=None, info=False):
    steps.append((label, cmds, hold_ or hold, info))


step('setup', OFF, 4)
feats = [f for f in F if scene in f['scenes'] and api in f['apis'] and (only is None or f['name'] in only)]
for f in feats:
    for r in range(reps):
        step(f['name'] + '.off', f['off'])
        for lab, cmds in f['levels']:
            step(f['name'] + '.' + lab, cmds)
    step(f['name'] + '.off', f['off'])
    step('reset', OFF, 2)
if only is None:
    for r in range(reps):
        step('cfg.off', OFF)
        step('cfg.default', DEFAULT_ON)
        step('cfg.ultra', DEFAULT_ON + ULTRA)
        if RT:
            step('cfg.ultra_rays', ULTRA_RT)
    step('cfg.off', OFF, 3, True)


def lua(s):
    return "'" + s.replace("'", "") + "'"


with open(out, 'w') as o:
    o.write('AB_PRESETS = { %s }\nAB_STEPS = {\n' % PRESETS[scene])
    for lab, cmds, h, info in steps:
        o.write("  { %s, { %s }, '%s', %s%s },\n" % (lua(lab), ', '.join(lua(c) for c in cmds), PRESET, h, ", 'info'" if info else ''))
    o.write('}\n')
print(scene, api, 'steps', len(steps), 'seconds', int(sum(s[2] + 3 * (i == 0) for i, s in enumerate(steps))))
