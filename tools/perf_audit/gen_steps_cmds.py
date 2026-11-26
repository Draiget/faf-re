"""the memory-per-feature steps: the shipped state first, then everything off, then one feature at a time on (cumulative)"""
def vram_steps(api):
    rt = api in ('d3d12', 'vulkan')
    s = [('start_default', []), ('all_off', ['sc_FrameTimeClamp 0', 'ren_DynLights 0', 'ren_ShadowFilter 0', 'ren_AmbientOcclusion 0', 'ren_Fxaa 0', 'ren_Sharpen 0', 'ren_Grade 0', 'ren_Taa 0', 'ren_RenderScale 1',
         'ren_SoftParticles 0', 'ren_ParticleLowRes 0', 'ren_WaterQuality 0', 'ren_WaterSSR 0', 'ren_WaterCaustics 0', 'ren_WaterAbsorb 0', 'ren_WaterSheen 0', 'ren_WaterUnitShadows 0', 'ren_WaterSim 0', 'ren_Atmosphere 0']),
         ('hold_off', [])]
    s += [('aa_fxaa', ['ren_Fxaa 1']), ('aa_smaa', ['ren_Fxaa 2']), ('sharpen_grade', ['ren_Sharpen 1', 'ren_Grade 1']), ('softparticles_high', ['ren_SoftParticles 2']),
          ('lowres_half_forced', ['ren_ParticleLowRes 1', 'ren_ParticleLowResMinViewport 0']), ('watersim', ['ren_WaterSim 1']), ('waterq3', ['ren_WaterQuality 3']), ('ssr_absorb_caustics', ['ren_WaterSSR 1', 'ren_WaterAbsorb 1', 'ren_WaterCaustics 100']),
          ('ao_standard', ['ren_AmbientOcclusion 1']), ('ao_high', ['ren_AmbientOcclusion 4']), ('shadowfilter_ultra', ['ren_ShadowFilter 4'])]
    if rt:
        s += [('lights_ultra', ['ren_DynLights 4']), ('taa', ['ren_Taa 1']), ('renderscale_75', ['ren_RenderScale 0.75']), ('atmosphere', ['ren_Atmosphere 1']), ('bloomwide', ['ren_BloomWide 2']),
              ('rays_shadows', ['ren_RayTracedShadows 1']), ('rays_ao_bounce_water', ['ren_RayAo 1', 'ren_RayBounce 1', 'ren_RayWaterReflections 1'])]
    s += [('final_hold', [])]
    return s
