# Recorder crash bisect / capture driver.
#
# Runs recorder.exe on the parity replay and classifies the outcome:
#   exit 0        clean end (parity heartbeat or clean exit)
#   exit 124      timeout (hooks installed, game alive: a non-crashing set)
#   exit 0xC...   the game died: for the all-functions crash, an AV inside the
#                 game (0xC0000005), which is what the bisect searches for.
# Optionally captures the fault under cdb when the run dies.
#
# usage: run_one.ps1 -Spec <spec.bin> -Out <table.txt> [-Capture <cdb.txt>] [-TimeoutSec 900] [-Tag <label>] [-MaxAttempts 3]
param(
  [Parameter(Mandatory = $true)][string]$Spec,
  [Parameter(Mandatory = $true)][string]$Out,
  [string]$Capture = "",
  [int]$TimeoutSec = 900,
  [string]$Tag = "run",
  [switch]$Probe,
  [int]$MaxAttempts = 3
)
$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$recorder = Join-Path $here 'build\recorder.exe'
$game = 'C:\ProgramData\FAForever\bin\ForgedAlliance.exe'
$replay = 'G:\projects\faf-main\tmp\parity\pool\26902315.scfareplay'
$work = Join-Path $here 'bisect'
New-Item -ItemType Directory -Force $work | Out-Null
function AbsPath([string]$p) {
  if ([System.IO.Path]::IsPathRooted($p)) { return [System.IO.Path]::GetFullPath($p) }
  return [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $p))
}
# The DLL opens RETAIL_RECORDER_OUT inside the game process, whose CWD is the
# game folder, so every path handed to the game must be absolute.
$Out = AbsPath $Out
if ($Capture -ne "") { $Capture = AbsPath $Capture }
$gameLog = Join-Path $work "game_$Tag.log"

$env:RETAIL_RECORDER_SPEC = AbsPath $Spec
$env:RETAIL_RECORDER_OUT = $Out
if ($Probe) {
  $env:RETAIL_RECORDER_PROBE = "1"
  $env:RETAIL_RECORDER_JOURNAL = AbsPath (Join-Path $work "journal_$Tag.txt")
} else {
  Remove-Item Env:\RETAIL_RECORDER_PROBE -ErrorAction SilentlyContinue
  Remove-Item Env:\RETAIL_RECORDER_JOURNAL -ErrorAction SilentlyContinue
}
function CountHeartbeats([string]$logPath) {
  if (-not (Test-Path $logPath)) { return 0 }
  return (Select-String -Path $logPath -Pattern 'PARITY heartbeat' -SimpleMatch:$false -ErrorAction SilentlyContinue | Measure-Object).Count
}

for ($attempt = 1; $attempt -le $MaxAttempts; ++$attempt) {
  & $recorder $Out $TimeoutSec $gameLog $game /init init_parity.lua /nobugreport /replay $replay /replayid 26902315 /nosound /nomovie /windowed 640 480 /log $gameLog 2>&1 | Tee-Object -Variable recorderOut | Out-Null
  $code = $LASTEXITCODE
  "[$Tag] exit=$code spec=$Spec attempt=$attempt" | Write-Host
  # A timeout with zero heartbeats never reached the sim: the map loader
  # stalled (observed even with no hooks installed). Retry from a clean
  # process state rather than reporting a false verdict.
  if ($code -eq 124 -and $attempt -lt $MaxAttempts -and (CountHeartbeats $gameLog) -eq 0) {
    "[$Tag] loader stall (no heartbeats); killing leftovers and retrying" | Write-Host
    Get-Process -Name ForgedAlliance, recorder -ErrorAction SilentlyContinue |
      Where-Object { $_.StartTime -gt (Get-Date).AddMinutes(-60) } | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep 3
    continue
  }
  break
}
if ($code -ne 0 -and $code -ne 124 -and $Capture -ne "" -and (Test-Path 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe')) {
  # cdb -c with nested quotes mangles under PowerShell; a command file does not.
  # .logopen keeps the kv/dds dump on disk even though `q` kills the pipe early.
  $cdbCmd = Join-Path $work "cdb_cmd_$Tag.txt"
  $cdbLog = Join-Path $work "cdb_log_$Tag.txt"
  Set-Content -Path $cdbCmd -Value ".logopen $cdbLog", 'sxe -c "g" av', 'g', 'r', 'kv 25', 'dds esp L30', 'q'
  & 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe' -g -G -cf $cdbCmd -o $recorder $Out 300 - $game /init init_parity.lua /nobugreport /replay $replay /replayid 26902315 /nosound /nomovie /windowed 640 480 /log $gameLog 2>&1 | Out-File -Encoding utf8 $Capture
  "[capture] $Capture" | Write-Host
}
# classify: 0xC0000005 (unsigned 3221225477) or its signed form -1073741819
if ($code -eq 3221225477 -or $code -eq -1073741819) { "CRASH" } elseif ($code -eq 0 -or $code -eq 124) { "OK" } else { "OTHER:$code" }
