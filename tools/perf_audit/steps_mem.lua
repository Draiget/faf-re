AB_PRESETS = { lake = { 60, 0.9, 0, -25, 0 }, close = { 25, 0.7, 0, -10, 20 } }
AB_STEPS = {
  { 'setup', { 'sc_FrameTimeClamp 0' }, 'lake', 8, 'info' },
  { 'meas', {}, 'close', 8, 'info' },
}
