# cost.ps1 -Builds master,pr02,...: GPU/CPU cost runs on D3D12, replay 28041625 at tick 9000, ships view, 75 s of running game with the render profile on; defaults and the PR's switches off
param([string[]]$Builds = @('master','pr02','pr03','pr04','pr05','pr06','pr07','pr09'), [string]$Tag = 'cost', [int]$Reps = 1, [string]$Api = 'd3d12')
$here = $PSScriptRoot
$offs = @{
  pr02 = @('ren_WaterSim 0','ren_WaterQuality 0','ren_WaterGrid 0','ren_WaterDomains 0','ren_ShoreTessCoeff 1','ren_ShoreTessCell 0','ren_ShorelineCutoff 1000','ren_TerrainWaterLevels 0');
  pr03 = @('ren_DynLights 0','ren_DynLightsWaterLevels 0'); pr04 = @('ren_ShadowFilter 0','ren_AmbientOcclusion 0');
  pr05 = @('ren_Atmosphere 0','ren_BloomWide 0','ren_Fxaa 0','ren_Grade 0','ren_Sharpen 0','ren_Taa 0','ren_RenderScale 1','ren_TextureAnisotropy 8');
  pr06 = @('ren_SoftParticles 0','ren_ParticleLowRes 0','ren_MaxFps 0','ren_FpsLimit 0');
  pr07 = @('ren_WaterSSR 0','ren_WaterCaustics 0','ren_WaterAbsorb 0','ren_WaterSheen 0','ren_WaterUnitShadows 0');
  pr09 = @('ren_River 0','ren_Waterfalls 0','ren_WaterBanks 0')
}
foreach ($rep in 1..$Reps) {
foreach ($b in $Builds) {
  foreach ($cfg in 'default','off') {
    if ($b -eq 'master' -and $cfg -eq 'off') { continue }
    $cmds = if ($cfg -eq 'off') { $offs[$b] } else { @() }
    $q = ($cmds | ForEach-Object { "'$_'" }) -join ','
    $sc = "$here\scenes_cost.lua"
    Set-Content $sc "EV_TICK = 9000`nEV_MEASURE = 75`nEV_SCENES = { { 'ships', {390,0,400}, {0, 0.9}, 60 } }`nEV_CMDS = { $q }`n" -Encoding ascii
    $out = "$here\out\$Tag\${b}_${cfg}_$Api`_r$rep"
    & "$here\ev_run.ps1" -Name $b -Api $Api -Replay 28041625 -Init 'C:/ProgramData/FAForever/bin_x64_ev/init_m28.lua' -Scenes $sc -Out $out -Timeout 400 -Profile 120 -NoDump -Camera ev_perf_camera.lua
  }
}
}
"COST DONE"
