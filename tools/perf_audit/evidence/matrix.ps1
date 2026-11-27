# matrix.ps1 -Name master -Tag master_a -Groups sr,astro,levels,rivers -Apis d3d11,d3d12,vulkan
param([string]$Name, [string]$Tag, [string[]]$Groups = @('sr','astro','levels','rivers'), [string[]]$Apis = @('d3d11','d3d12','vulkan'), [string]$Con = '', [switch]$NoOff, [string[]]$OffCmds = @())
$here = $PSScriptRoot
$cfg = @{
  sr     = @{ Replay = '28041625'; Init = 'C:/ProgramData/FAForever/bin_x64_ev/init_m28.lua'; Map = '' }
  astro  = @{ Replay = '28013263'; Init = 'C:/ProgramData/FAForever/bin/init_faf.lua'; Map = '' }
  levels = @{ Replay = ''; Init = 'C:/ProgramData/FAForever/bin/init_faf.lua'; Map = '/maps/faf_re_waterlevels/faf_re_waterlevels_scenario.lua' }
  rivers = @{ Replay = ''; Init = 'C:/ProgramData/FAForever/bin/init_faf.lua'; Map = '/maps/faf_re_waterrivers/faf_re_waterrivers_scenario.lua' }
}
foreach ($g in $Groups) {
  foreach ($api in $Apis) {
    $out = "$here\out\$Tag\${g}_$api"
    if (Test-Path "$out\run.json") { continue }
    $c = $cfg[$g]
    $scenes = "$here\scenes_$g.lua"
    $offStr = ($OffCmds | ForEach-Object { "'$_'" }) -join ','
    $tmp = "$here\scenes_${g}_x.lua"; (Get-Content $scenes -Raw).Replace('__OFF__', $offStr) | Set-Content $tmp -Encoding ascii; $scenes = $tmp
    if ($NoOff) { $scenes = "$here\scenes_${g}_m.lua"; (Get-Content $tmp | Where-Object { $_ -notmatch '_off' }) | Set-Content $scenes -Encoding ascii }
    $con2 = $Con; if ($g -eq 'rivers') { $con2 = 'sim_FixWaterBodies=1;sim_FixRivers=1' }
    & "$here\ev_run.ps1" -Name $Name -Api $api -Replay $c.Replay -Map $c.Map -Init $c.Init -Scenes $scenes -Out $out -Timeout 420 -Con $con2
  }
}
"MATRIX DONE $Name $Tag"



