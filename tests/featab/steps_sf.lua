AB_PRESETS = {
    close = { 18, 0.5, 0, -20, 4 },
    closer = { 9, 0.5, 0, -20, 6 },
}
AB_STEPS = {
    { 'warm', { 'ren_ShadowFilter 0' }, 'close' },
    { 'off_close', { 'ren_ShadowFilter 0' }, 'close' },
    { 'low_close', { 'ren_ShadowFilter 1' }, 'close' },
    { 'med_close', { 'ren_ShadowFilter 2' }, 'close' },
    { 'high_close', { 'ren_ShadowFilter 3' }, 'close' },
    { 'ultra_close', { 'ren_ShadowFilter 4' }, 'close' },
    { 'off_closer', { 'ren_ShadowFilter 0' }, 'closer' },
    { 'med_closer', { 'ren_ShadowFilter 2' }, 'closer' },
    { 'ultra_closer', { 'ren_ShadowFilter 4' }, 'closer' },
    { 'off_again', { 'ren_ShadowFilter 0' }, 'closer' },
}
