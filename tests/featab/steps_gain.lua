AB_PRESETS = { z40 = { 40, 1.1, 0.8, 0, 0 }, z90 = { 90, 1.1, 0.8, 0, 0 } }
AB_STEPS = {
  { 'off40', { 'ren_DynLights 0' }, 'z40' },
  { 'g0_40', { 'ren_DynLights 4', 'ren_DynLightsGain 0' }, 'z40' },
  { 'g100_40', { 'ren_DynLightsGain 100' }, 'z40' },
  { 'g300_40', { 'ren_DynLightsGain 300' }, 'z40' },
  { 'g1000_40', { 'ren_DynLightsGain 1000' }, 'z40' },
  { 'off90', { 'ren_DynLights 0' }, 'z90' },
  { 'g100_90', { 'ren_DynLights 4', 'ren_DynLightsGain 100' }, 'z90' },
  { 'g300_90', { 'ren_DynLightsGain 300' }, 'z90' },
}
