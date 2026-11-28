# -Prefs <name>: a preferences file next to Game.prefs to run with (a copy with other options; the profile of the player is not touched)
# Needs a copy of the engine folder with the two scene hooks (tests/lights/ingame/hooks: append simInit.lua and gamemain.lua to
# <bin>\fafengine\lua\simInit.lua and <bin>\fafengine\lua\ui\game\gamemain.lua); set FAF_BIN to that folder.
# usage: featab.ps1 -Api d3d12 -Exe main_x64_lrfix -Scene static|nuke|scan -Tag t1 [-Steps steps_static.lua] [-Tx 0 -Ty 0 -Tz 0] [-PauseAt 0] [-Hold 6] [-Start 14]
# Frames go to out\featab_<tag>_<api>\, steps.csv lists "step,label,frameIndexAtStepStart" (frames are 1 per second).
param([string]$Api = 'd3d12', [string]$Exe = 'main_x64_lrfix', [string]$Scene = 'static', [string]$Tag = 't1', [string]$Steps = 'steps_static.lua',
      [double]$Tx = 0, [double]$Ty = 0, [double]$Tz = 0, [double]$PauseAt = 0, [int]$Hold = 6, [int]$Start = 14, [int]$Timeout = 420, [int]$Width = 1600, [int]$Height = 900, [int]$Focus = 0, [int]$Select = 0, [string]$Map = '/maps/adaptive_acid_lakes.v0004/adaptive_acid_lakes_scenario.lua', [string]$ExtraCon = '', [string]$Prefs = '', [string[]]$ExtraArgs = @())
$bin = if ($env:FAF_BIN) { $env:FAF_BIN } else { 'C:\ProgramData\FAForever\bin_x64' } # the folder with the exe and its fafengine: use a private copy, the script writes the scene scripts into $bin\fafengine\lua\test
$logs = 'C:\ProgramData\FAForever\logs'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$test = "$bin\fafengine\lua\test"
$out = if ($env:FEATAB_OUT) { $env:FEATAB_OUT } else { "$here\..\..\out" }
$dump = "$out\featab_${Tag}_$Api"
Remove-Item $dump -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $dump -Force | Out-Null
foreach ($f in 'dynlights_test.lua', 'dynlights_camera.lua') { if (Test-Path "$test\$f") { Copy-Item "$test\$f" "$test\$f.bak_featab" -Force } }
$sceneHeader = "AB_SCENE = '$Scene'`nAB_TX = $Tx`nAB_TZ = $Tz`n"
if ($env:FEATAB_SHIELDUNIT) { $sceneHeader += "AB_SHIELDUNIT = '$($env:FEATAB_SHIELDUNIT)'`n" }
if ($env:FEATAB_NOSHIELD) { $sceneHeader += "AB_NOSHIELD = true`n" }
if ($env:FEATAB_COUNT) { $sceneHeader += "AB_COUNT = $($env:FEATAB_COUNT)`n" }
if ($env:FEATAB_SHIP) { $sceneHeader += "AB_SHIP = '$($env:FEATAB_SHIP)'`n" }
if ($env:FEATAB_SPAN) { $sceneHeader += "AB_SPAN = $($env:FEATAB_SPAN)`n" }
if ($env:FEATAB_SHOOTER) { $sceneHeader += "AB_SHOOTER = '$($env:FEATAB_SHOOTER)'`n" }
if ($env:FEATAB_SIZES) { $sceneHeader += "AB_SIZES = { $($env:FEATAB_SIZES) }`n" }
Set-Content "$test\dynlights_test.lua" ($sceneHeader + (Get-Content "$here\featab_scene.lua" -Raw)) -Encoding ascii
$camHeader = "AB_START = $Start`nAB_HOLD = $Hold`nAB_TX = $Tx`nAB_TY = $Ty`nAB_TZ = $Tz`nAB_PAUSE_AT = $PauseAt`nAB_FOCUS = $Focus`nAB_SELECT = $($Select -ne 0 ? 'true' : 'false')`n"
if ($Scene -eq 'scan') { $camHeader += "AB_STEPS = {}`nAB_PRESETS = {}`n"; $stepsText = '' } else { $stepsText = Get-Content "$here\$Steps" -Raw }
Set-Content "$test\dynlights_camera.lua" ($camHeader + $stepsText + "`n" + (Get-Content "$here\featab_camera.lua" -Raw)) -Encoding ascii
$env:FAF_CRASH_NO_DIALOG = '1'
$env:FAF_GAL_DUMP_DIR = $dump
$env:FAF_GAL_DUMP_SECONDS = $(if ($env:FEATAB_DUMP) { $env:FEATAB_DUMP } else { '1' })
if ($env:FEATAB_DUMP_MS) { $env:FAF_GAL_DUMP_MS = $env:FEATAB_DUMP_MS } else { $env:FAF_GAL_DUMP_MS = $null }
$log = "$logs\featab_${Tag}_$Api.log"
Remove-Item $log -ErrorAction SilentlyContinue
$prefsArgs = if ($Prefs) { @('/prefs', $Prefs) } else { @() }
$p = Start-Process -FilePath "$bin\$Exe.exe" -WorkingDirectory $bin -PassThru -ArgumentList (@(
  '/init', 'C:/ProgramData/FAForever/bin/init_faf.lua', '/nobugreport', '/log', $log, "/$Api", '/windowed', "$Width", "$Height", '/nomovie', '/nosound',
  '/seed', '7', '/noai', '/faction', '1', '/map', $Map,
  '/con', 'ren_DynLights=0' + $ExtraCon) + $prefsArgs + $ExtraArgs)
$deadline = (Get-Date).AddSeconds($Timeout)
$state = 'timeout'
$seen = 0
$csv = @()
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Milliseconds 400
  if ($p.HasExited) { $state = 'exited'; break }
  if (Test-Path $log) {
    $t = Get-Content $log -ErrorAction SilentlyContinue
    foreach ($m in ($t | Select-String 'FEATAB: step (\d+) (.*)$')) {
      $n = [int]$m.Matches[0].Groups[1].Value
      if ($n -gt $seen) { $seen = $n; $csv += "$n,$($m.Matches[0].Groups[2].Value),$((Get-ChildItem $dump -Filter *.bmp).Count)" }
    }
    $s = $t -join "`n"
    if ($Scene -eq 'scan' -and $s -match 'FEATAB: \[[\d.]+ s\] (water at|no water)') { $state = 'scan'; break }
    if ($s -match 'FEATAB: ab done') { Start-Sleep -Seconds 2; $state = 'done'; break }
    if ($s -match 'info: CRASH') { $state = 'crash'; break }
  }
}
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
foreach ($f in 'dynlights_test.lua', 'dynlights_camera.lua') { if (Test-Path "$test\$f.bak_featab") { Move-Item "$test\$f.bak_featab" "$test\$f" -Force } else { Remove-Item "$test\$f" -Force -ErrorAction SilentlyContinue } }
Set-Content "$dump\steps.csv" $csv
"$Tag $Api -> $state, $((Get-ChildItem $dump -Filter *.bmp).Count) frames"
Get-Content $log | Select-String 'FEATAB: \[' | ForEach-Object { $_.Line }
