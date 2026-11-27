# ev_run.ps1 -Name pr02 -Api d3d12 -Replay 28041625 -Scenes scenes_x.lua -Out dir [-Prefs file] [-Env 'A=1;B=2'] [-Map path] [-Dump 1]
# Starts the staged build, plays the replay, runs ev_camera.lua with the scenes, collects the frame dumps next to the log, maps scenes to dumps by time.
param([string]$Name, [string]$Api = 'd3d12', [string]$Replay = '', [string]$Map = '', [string]$Scenes, [string]$Out, [string]$Prefs = 'Game_ev.prefs', [string]$Env = '',
      [int]$Width = 1600, [int]$Height = 900, [int]$Timeout = 600, [int]$Profile = 0, [string[]]$ExtraArgs = @(), [string]$Con = '', [string]$Init = 'C:/ProgramData/FAForever/bin/init_faf.lua', [string]$Camera = 'ev_camera.lua', [switch]$NoDump)
$here = $PSScriptRoot
$replays = if ($env:FAF_REPLAYS) { $env:FAF_REPLAYS } else { "$env:USERPROFILE\Documents\GitHub\replays_pr" }
$bin = "C:\ProgramData\FAForever\bin_x64_ev\$Name"
New-Item -ItemType Directory $Out -Force | Out-Null
$test = "$bin\fafengine\lua\test"
Set-Content "$test\ev_camera.lua" ((Get-Content $Scenes -Raw) + "`n" + (Get-Content "$here\$Camera" -Raw)) -Encoding ascii
$log = "$Out\game.log"
Remove-Item $log -ErrorAction SilentlyContinue
Get-ChildItem $Out -Filter '*.bmp' -ErrorAction SilentlyContinue | Remove-Item -Force
Get-ChildItem $Out -Filter '*.png' -ErrorAction SilentlyContinue | Remove-Item -Force
$env:FAF_CRASH_NO_DIALOG = '1'
if ($NoDump) { $env:FAF_GAL_DUMP_DIR = $null; $env:FAF_GAL_DUMP_SECONDS = $null } else { $env:FAF_GAL_DUMP_DIR = $Out.Replace('\', '/'); $env:FAF_GAL_DUMP_SECONDS = '1' }
$env:FAF_GPU_PROFILE = if ($Profile -gt 0) { "$Profile" } else { $null }
$env:FAF_SHADER_CACHE_DIR = $null
foreach ($kv in ($Env -split ';')) { if ($kv -match '^(\w+)=(.*)$') { Set-Item "env:$($Matches[1])" $Matches[2] } }
$args0 = @('/init', $Init, '/nobugreport', '/log', $log, "/$Api", '/windowed', "$Width", "$Height", '/nomovie', '/nosound')
if ($Replay) { $args0 += @('/replay', "$replays\$Replay.scfareplay", '/replayid', $Replay) }
else { $args0 += @('/seed', '7', '/noai', '/faction', '1', '/map', $Map) }
if ($Prefs) { $args0 += @('/prefs', $Prefs) }
if ($Con) { $args0 += @('/con', $Con) }
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$p = Start-Process -FilePath "$bin\ev.exe" -WorkingDirectory $bin -PassThru -ArgumentList ($args0 + $ExtraArgs)
$markers = [ordered]@{}; $fs = $null; $sr = $null; $state = 'timeout'
while ($sw.Elapsed.TotalSeconds -lt $Timeout) {
  Start-Sleep -Milliseconds 100
  if ($p.HasExited) { $state = 'exited'; break }
  if ($null -eq $sr -and (Test-Path $log)) { try { $fs = [System.IO.File]::Open($log, 'Open', 'Read', 'ReadWrite'); $sr = New-Object System.IO.StreamReader($fs) } catch { $sr = $null } }
  if ($sr) {
    while ($null -ne ($ln = $sr.ReadLine())) {
      if ($ln -match 'EV: (paused.*|scene \d+ .*|done)') { $markers["$($Matches[1])"] = [math]::Round($sw.Elapsed.TotalSeconds, 2); if ($Matches[1] -eq 'done') { $state = 'done' } }
      if ($ln -match 'info: CRASH') { $state = 'crash' }
    }
  }
  if ($state -ne 'timeout') { Start-Sleep -Milliseconds 1500; break }
}
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
if ($sr) { $sr.Close() }
$dumps = Get-ChildItem $Out -Include '*.bmp', '*.png' -Recurse | Sort-Object LastWriteTime
$o = [pscustomobject]@{ name = $Name; api = $Api; state = $state; total = [math]::Round($sw.Elapsed.TotalSeconds, 1); markers = $markers; dumps = @($dumps | ForEach-Object { [pscustomobject]@{ f = $_.Name; mt = $_.LastWriteTime.ToString('o') } }); start = (Get-Date).AddSeconds(-$sw.Elapsed.TotalSeconds).ToString('o') }
$o | ConvertTo-Json -Depth 5 | Set-Content "$Out\run.json" -Encoding ascii
"$Name $Api -> $state in $([math]::Round($sw.Elapsed.TotalSeconds,1)) s; $($markers.Count) markers; $($dumps.Count) dumps"



