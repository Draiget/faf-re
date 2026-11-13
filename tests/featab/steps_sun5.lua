AB_PRESETS = {
    mid = { 60, 0.9, 0, 0, 0 },
    low = { 25, 0.45, 0, 0, 0 },
}
AB_STEPS = {
    { 'warm', { 'ren_DynLights 4', 'ren_DynLightsMode 1', 'ren_DynLightsSunShadows 1' }, 'mid' },
    { 'sun_mid', { 'ren_DynLightsSunShadows 1' }, 'mid' },
    { 'off_mid', { 'ren_DynLightsSunShadows 0' }, 'mid' },
    { 'sun_low', { 'ren_DynLightsSunShadows 1' }, 'low' },
    { 'off_low', { 'ren_DynLightsSunShadows 0' }, 'low' },
}
