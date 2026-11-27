# on.ps1: frames and cost with the default-off features switched on (PR03 lights, PR04 shadow filter + GTAO, PR05 SMAA + render scale + wide bloom). 
$here = $PSScriptRoot
$on = @{ pr03 = @('ren_DynLights 3'); pr04 = @('ren_ShadowFilter 3','ren_AmbientOcclusion 4'); pr05 = @('ren_Fxaa 2','ren_RenderScale 0.75','ren_BloomWide 1') }
$cfg = @{
  sr    = @{ Replay = '28041625'; Init = 'C:/ProgramData/FAForever/bin_x64_ev/init_m28.lua'
             Scenes = "{ 'ships_on', {390,0,400}, {0, 0.9}, 60, { }, 5 },{ 'coast_near_on', {330,0,420}, {0, 0.9}, 90, { }, 5 }"; Warm = "{390,0,400}, {0, 0.9}, 60" }
  astro = @{ Replay = '28013263'; Init = 'C:/ProgramData/FAForever/bin/init_faf.lua'
             Scenes = "{ 'nowater_wide_on', 'center', {0, 1}, 500, { }, 5 },{ 'nowater_mid_on', 'center', {0, 0.9}, 150, { }, 5 }"; Warm = "'center', {0, 0.9}, 150" }
}
$tick = @{ sr = 9000; astro = 12000 }
foreach ($pr in 'pr03','pr04','pr05') {
  $q = ($on[$pr] | ForEach-Object { "'$_'" }) -join ','
  foreach ($g in 'sr','astro') { foreach ($api in 'd3d11','d3d12','vulkan') {
    $out = "$here\out\${pr}_on\${g}_$api"
    if (Test-Path "$out\run.json") { continue }
    $c = $cfg[$g]
    $sc = "$here\scenes_${g}_on.lua"
    Set-Content $sc "EV_TICK = $($tick[$g])`nEV_HIDE_UI = true`nEV_SCENES = {`n  { 'warm', $($c.Warm), { $q }, 45 },`n  $($c.Scenes)`n}`n" -Encoding ascii
    & "$here\ev_run.ps1" -Name $pr -Api $api -Replay $c.Replay -Init $c.Init -Scenes $sc -Out $out -Timeout 420
  } }
  $sc = "$here\scenes_cost.lua"
  Set-Content $sc "EV_TICK = 9000`nEV_MEASURE = 75`nEV_SCENES = { { 'ships', {390,0,400}, {0, 0.9}, 60 } }`nEV_CMDS = { $q }`n" -Encoding ascii
  & "$here\ev_run.ps1" -Name $pr -Api d3d12 -Replay 28041625 -Init 'C:/ProgramData/FAForever/bin_x64_ev/init_m28.lua' -Scenes $sc -Out "$here\out\cost\${pr}_on_d3d12_r1" -Timeout 400 -Profile 120 -NoDump -Camera ev_perf_camera.lua
}
"ON DONE" | Add-Content "$here\all_after.txt"
