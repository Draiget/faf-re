# Runs an in-game test map on the engine built from this checkout, copied as main_x64_mapfmt.exe (never main_x64.exe).
# Needs the maps of make_testmaps.py in the user Maps folder. Optional screenshot: set MAPFMT_SCREENSHOT_PY to a script taking <out.png> --pid N.
# Example: .\run_map.ps1 -Stem mapfmt_ext_a -Tag a -Api /d3d11 -ShotDelay 30
param([string]$Stem, [string]$Tag, [int]$ShotDelay = 12, [string]$Api = '/d3d12')
$ErrorActionPreference = 'Continue'
$wt = (Resolve-Path "$PSScriptRoot\..\..\..").Path
$scratch = $env:TEMP
Copy-Item "$wt\build\clang-x64-release\src\main_x64.exe" C:\ProgramData\FAForever\bin_x64\main_x64_mapfmt.exe -Force
Copy-Item "$wt\build\clang-x64-release\src\main_x64.pdb" C:\ProgramData\FAForever\bin_x64\main_x64_mapfmt.pdb -Force
$log = "$wt\mapfmt_$Tag.log"
if (Test-Path $log) { Remove-Item $log }
$p = Start-Process -FilePath C:\ProgramData\FAForever\bin_x64\main_x64_mapfmt.exe -WorkingDirectory C:\ProgramData\FAForever\bin `
  -ArgumentList @('/init', 'C:\ProgramData\FAForever\bin\init_faf.lua', $Api, '/windowed', '1280', '720', '/nomovie', '/nosound', '/nobugreport',
                  '/log', $log, '/seed', '7', '/faction', '1', '/map', "/maps/$Stem/${Stem}_scenario.lua") -PassThru
"PID $($p.Id)"
$done = $false
foreach ($i in 1..18) {
  Start-Sleep -Seconds 5
  $p.Refresh()
  if ($p.HasExited) { "exited $($p.ExitCode)"; break }
  if ((Test-Path $log) -and (Select-String -Path $log -Pattern 'MAPFMT-TEST done' -Quiet)) { $done = $true; break }
}
if ($done -and -not $p.HasExited) {
  Start-Sleep -Seconds $ShotDelay
  & python $env:MAPFMT_SCREENSHOT_PY "$scratch\shot_$Tag.png" --pid $p.Id
}
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force; "stopped PID $($p.Id)" }
Get-Content $log -ErrorAction SilentlyContinue | Select-String 'MAPFMT|MapFormat' | ForEach-Object { $_.Line }
Get-Content $log -ErrorAction SilentlyContinue | Select-String "Can't find texture|rror running|nonexistent global|crash|Unhandled|assert" | Where-Object { $_.Line -notmatch 'GetRenderFeatures' } | Select-Object -First 12 | ForEach-Object { $_.Line }
