-- the water-levels overview with master's terrain shadows value (ren_TerrainShadows 0.45) against the PR 07 default (0): the default change of PR 07
EV_TICK = false
EV_SPEED = 1
EV_PAUSE_AT = 12
EV_HIDE_UI = true
EV_SETTLE = 14
EV_SCENES = {
  { 'overview', 'center', {0, 1.1}, 350, {  }, 5 },
  { 'overview_ts', 'center', {0, 1.1}, 350, { 'ren_TerrainShadows 0.45' }, 5 },
}
