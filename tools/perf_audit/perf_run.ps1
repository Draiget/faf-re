# perf audit runner. usage: perf_run.ps1 -Exe perf|perfbase -Api d3d11|d3d12|vulkan -Tag x -Scene static|soak|nuke|none|falls -Steps steps_x.lua [-Prefs Game_perf_off.prefs]
#   [-Hold 4] [-Start 12] [-PauseAt 0] [-Count 40] [-Map ...] [-ExtraCon 'a=1;b=2'] [-Cache default|private|cold] [-Mem 0|1] [-Interval 120] [-Tx -Ty -Tz]
# Output: logs\pf_<tag>_<api>_<exe>.log, perf_out\<tag>_<api>_<exe>.json (marker times, memory samples). Stops the game by PID.
param([string]$Exe = 'perf', [string]$Api = 'd3d12', [string]$Tag = 't1', [string]$Scene = 'static', [string]$Steps = 'steps_x.lua',
      [string]$Prefs = '', [int]$Hold = 4, [int]$Start = 12, [double]$PauseAt = 0, [int]$Count = 40, [int]$Timeout = 900,
      [string]$Map = '/maps/adaptive_acid_lakes.v0004/adaptive_acid_lakes_scenario.lua', [string]$ExtraCon = '', [string]$Cache = 'default',
      [int]$Mem = 0, [int]$Interval = 120, [double]$Tx = 0, [double]$Ty = 0, [double]$Tz = 0, [int]$Width = 1600, [int]$Height = 900,
      [string[]]$ExtraArgs = @(), [int]$NoSceneHooks = 0, [string]$EnvExtra = '', [int]$QuietWait = 300, [string]$CacheDir = '', [int]$CacheClear = 0)
$here = $PSScriptRoot.Replace([string][char]92, '/')
$S = if ($env:PERF_AUDIT_OUT) { $env:PERF_AUDIT_OUT.Replace([string][char]92, '/') } else { "$here/out" }
New-Item -ItemType Directory "$S/perf_out" -Force | Out-Null
$bin = if ($env:PERF_BIN) { $env:PERF_BIN } else { 'C:/ProgramData/FAForever/bin_x64_perf' }
$logs = if ($env:FAF_LOGS) { $env:FAF_LOGS } else { 'C:\ProgramData\FAForever\logs' }
$fe = "$bin\fafengine"
if (Test-Path $fe) { Remove-Item $fe -Recurse -Force }
Copy-Item "$bin\fafengine_$Exe" $fe -Recurse
$test = "$fe\lua\test"
New-Item -ItemType Directory $test -Force | Out-Null
# wait (up to $QuietWait s) until no other game process runs; then go on and record the contention (other sessions' headless games
# use CPU but not the GPU, so GPU times stay valid and CPU times carry a note)
$waited = 0; $contended = ''
while ($true) {
  $busy = Get-Process | Where-Object { $_.ProcessName -match '^(vall|fix.*|riversim|vnext|headless|fafre_.*|ForgedAlliance.*|main_x64)$' }
  $gameGpu = $busy | Where-Object { $_.ProcessName -notmatch 'headless' }
  if (-not $busy) { break }
  if ($gameGpu) { Start-Sleep -Seconds 10; $waited += 10; if ($waited -gt 3600) { "BUSY (GPU game) after 60 min: $($gameGpu.ProcessName -join ',')"; exit 2 }; continue }
  if ($waited -ge $QuietWait) { $contended = 'headless:' + (($busy.ProcessName | Select-Object -Unique) -join ','); break }
  Start-Sleep -Seconds 10; $waited += 10
}
if ($waited -gt 0) { "waited $waited s; $contended" }
$cpu0 = (Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'").PercentProcessorTime
$sceneHeader = "AB_SCENE = '$Scene'`nAB_TX = $Tx`nAB_TZ = $Tz`nAB_COUNT = $Count`n"
$sceneFile = if ($Scene -eq 'falls') { "$here/scene_falls.lua" } elseif ($Scene -eq 'terraform') { "$here/scene_terraform.lua" } else { "$here/scene_main.lua" }
if ($Scene -eq 'falls') { $sceneHeader = '' }
Set-Content "$test\dynlights_test.lua" ($sceneHeader + (Get-Content $sceneFile -Raw)) -Encoding ascii
$camHeader = "AB_START = $Start`nAB_HOLD = $Hold`nAB_TX = $Tx`nAB_TY = $Ty`nAB_TZ = $Tz`nAB_PAUSE_AT = $PauseAt`n"
Set-Content "$test\dynlights_camera.lua" ($camHeader + (Get-Content "$here/$Steps" -Raw) + "`n" + (Get-Content "$here/perf_camera.lua" -Raw)) -Encoding ascii
$env:FAF_CRASH_NO_DIALOG = '1'
$env:FAF_GPU_PROFILE = "$Interval"
$env:FAF_GAL_DUMP_DIR = $null; $env:FAF_GAL_DUMP_SECONDS = $null; $env:FAF_GAL_DUMP_MS = $null
$env:FAF_NO_RENDER_ADDITIONS = $null
foreach ($kv in ($EnvExtra -split ';')) { if ($kv -match '^(\w+)=(.*)$') { Set-Item "env:$($Matches[1])" $Matches[2] } }
$cacheEff = ''
if ($CacheDir) {
  if ($CacheClear -eq 1) { Remove-Item $CacheDir -Recurse -Force -ErrorAction SilentlyContinue }
  New-Item -ItemType Directory "$CacheDir/effects" -Force | Out-Null
  $env:FAF_SHADER_CACHE_DIR = $CacheDir
  $ExtraArgs += @('/cachedir', "$CacheDir/effects")
}
elseif ($Cache -eq 'cold') { $cacheEff = "$S/perf_out/cache_cold_${Tag}_${Api}_$Exe"; Remove-Item $cacheEff -Recurse -Force -ErrorAction SilentlyContinue; New-Item -ItemType Directory $cacheEff -Force | Out-Null; $env:FAF_SHADER_CACHE_DIR = $cacheEff }
elseif ($Cache -eq 'private') { $cacheEff = "$S/perf_out/cache_${Exe}_$Api"; New-Item -ItemType Directory $cacheEff -Force | Out-Null; $env:FAF_SHADER_CACHE_DIR = $cacheEff }
else { $env:FAF_SHADER_CACHE_DIR = $null }
$log = "$logs\pf_${Tag}_${Api}_$Exe.log"
Remove-Item $log -ErrorAction SilentlyContinue
$prefsArgs = if ($Prefs) { @('/prefs', $Prefs) } else { @() }
$conArgs = if ($ExtraCon) { @('/con', $ExtraCon) } else { @() }
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$p = Start-Process -FilePath "$bin\$Exe.exe" -WorkingDirectory $bin -PassThru -ArgumentList (@(
  '/init', 'C:/ProgramData/FAForever/bin/init_faf.lua', '/nobugreport', '/log', $log, "/$Api", '/windowed', "$Width", "$Height", '/nomovie', '/nosound',
  '/seed', '7', '/noai', '/faction', '1', '/map', $Map) + $conArgs + $prefsArgs + $ExtraArgs)
$markers = [ordered]@{}
$memSamples = @()
$patterns = [ordered]@{
  first_log = '^info: Engine build'; renderer_ready = ': ready \('; shaders_compiled = 'SHADERS COMPILED'; blueprints_done = 'Blueprints Loading\.\.\. completed';
  sim_init = 'Lua sim environment initialized'; first_profile = 'Render profile over'; ready = 'PERF: ready at'; first_step = 'PERF: step 1 '; done = 'PERF: done'
}
$fs = $null; $sr = $null; $lineBuf = New-Object System.Collections.Generic.List[string]
$deadline = (Get-Date).AddSeconds($Timeout)
$state = 'timeout'; $lastMem = 0
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Milliseconds 50
  if ($p.HasExited) { $state = 'exited'; break }
  if ($null -eq $sr -and (Test-Path $log)) {
    try { $fs = [System.IO.File]::Open($log, 'Open', 'Read', 'ReadWrite'); $sr = New-Object System.IO.StreamReader($fs) } catch { $sr = $null }
  }
  if ($sr) {
    while ($null -ne ($ln = $sr.ReadLine())) {
      $t = $sw.Elapsed.TotalSeconds
      foreach ($k in $patterns.Keys) { if (-not $markers.Contains($k) -and $ln -match $patterns[$k]) { $markers[$k] = [math]::Round($t, 2) } }
      if ($ln -match 'effects: .*: (\d+) of (\d+) shaders read from the cache ahead of use, (\d+) queued') { $script:cacheMiss += [int]$Matches[3] }
      if ($ln -match 'PERF: done') { $state = 'done' }
      if ($ln -match 'info: CRASH') { $state = 'crash' }
    }
  }
  if ($state -ne 'timeout') { Start-Sleep -Milliseconds 1500; break }
  if ($sw.Elapsed.TotalSeconds - $lastMem -ge 2) {
    $lastMem = $sw.Elapsed.TotalSeconds
    try {
      $p.Refresh()
      $gpuMb = -1
      if ($Mem -eq 1) {
        $g = Get-CimInstance Win32_PerfFormattedData_GPUPerformanceCounters_GPUProcessMemory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "pid_$($p.Id)_*" }
        if ($g) { $gpuMb = [math]::Round((($g | Measure-Object DedicatedUsage -Sum).Sum) / 1MB, 1) }
      }
      $memSamples += [pscustomobject]@{ t = [math]::Round($lastMem, 1); priv = [math]::Round($p.PrivateMemorySize64 / 1MB, 1); ws = [math]::Round($p.WorkingSet64 / 1MB, 1); gpu = $gpuMb }
    } catch {}
  }
}
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
if ($sr) { $sr.Close() }
Remove-Item "$test\dynlights_test.lua", "$test\dynlights_camera.lua" -Force -ErrorAction SilentlyContinue
$out = [pscustomobject]@{ exe = $Exe; api = $Api; tag = $Tag; state = $state; contended = $contended; cpu0 = $cpu0; markers = $markers; mem = $memSamples; total_s = [math]::Round($sw.Elapsed.TotalSeconds, 1) }
$out | ConvertTo-Json -Depth 5 | Set-Content "$S/perf_out/${Tag}_${Api}_$Exe.json" -Encoding ascii
"$Tag $Api $Exe -> $state in $([math]::Round($sw.Elapsed.TotalSeconds,1)) s; markers: $(($markers.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' ')"
