# wd0.ps1: PR02 and master with master's detailed water off (ren_WaterDetail 0) on D3D12 / Vulkan, the ships and coast scenes.
$here = $PSScriptRoot
foreach ($b in 'master','pr02') {
  foreach ($api in 'd3d12','vulkan') {
    $out = "$here\out\${b}_wd0\sr_$api"
    if (Test-Path "$out\run.json") { continue }
    & "$here\ev_run.ps1" -Name $b -Api $api -Replay 28041625 -Init 'C:/ProgramData/FAForever/bin_x64_ev/init_m28.lua' -Scenes "$here\scenes_sr_m.lua" -Out $out -Timeout 420 -Con 'ren_WaterDetail=0'
  }
}
"WD0 DONE" | Add-Content "$here\all_after.txt"
