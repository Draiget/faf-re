# Checks a FAF_CALL_HASH_BUILD x86 headless against tests/replay_sets, with no original game.
#
# usage: check_replay_sets.ps1 -BuildDir <cmake build dir> [-Replay <id>] [-Pool <folder of replays>] [-Tag <run name>]
#
# Without -Replay it plays every replay in tests/replay_sets/replays.tsv. Needs build.bat's
# recorder.exe and recorder.dll, and the game folder with the init files (tools/replay-parity writes
# them). The exe is copied there under a test name; the playable one stays.
# Exit code: 0 all stored hashes found and every recorded checksum matched, 1 otherwise.
param(
  [Parameter(Mandatory = $true)][string]$BuildDir,
  [string]$Replay = '',
  [string]$Pool = 'G:\projects\faf-main\tmp\parity\pool',
  [string]$GameBin = 'C:\ProgramData\FAForever\bin',
  [string]$Tag = 'replaysets',
  [int]$TimeoutSec = 5400
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Resolve-Path (Join-Path $here '..\..')
$golden = Join-Path $repo 'tests\replay_sets'
$python = if ($env:FAF_PYTHON) { $env:FAF_PYTHON } else { 'python' }
$work = Join-Path $here 'bisect'
New-Item -ItemType Directory -Force $work | Out-Null

$exe = Join-Path $GameBin "${Tag}_test_headless.exe"
Copy-Item (Join-Path $BuildDir 'src\headless.exe') $exe -Force
Copy-Item (Join-Path $BuildDir 'src\headless.pdb') (Join-Path $GameBin "${Tag}_test_headless.pdb") -Force

$env:RETAIL_RECORDER_SIM_ENTRY = '0x00749F40'
$env:RETAIL_RECORDER_INJECT_DELAY_MS = '200'
$allPassed = $true
foreach ($line in Get-Content (Join-Path $golden 'replays.tsv')) {
  $id, $init, $beats = $line -split "`t"
  if ($id -eq 'replay' -or ($Replay -ne '' -and $id -ne $Replay)) { continue }
  $run = "$Tag$id"
  $spec = Join-Path $work "$run.bin"
  & $python (Join-Path $here 'replay_sets.py') spec $golden $id (Join-Path $BuildDir 'src\headless.exe') (Join-Path $BuildDir 'src\headless.pdb') $spec
  if ($LASTEXITCODE -ne 0) { exit 1 }

  $env:RETAIL_RECORDER_SPEC = $spec
  $env:RETAIL_RECORDER_SETS = Join-Path $work "$run.sets"
  $env:RETAIL_RECORDER_SIM_BEATS = $beats
  $log = Join-Path $work "$run.log"
  $console = Join-Path $work "$run.console"
  & (Join-Path $here 'build\recorder.exe') (Join-Path $work "$run.out") $TimeoutSec $log $exe --replay (Join-Path $Pool "$id.scfareplay") /init (Join-Path $GameBin $init) /nosound /log $log /simworkers 0 --label replay 2>&1 | Out-File -Encoding ascii $console
  $verdict = Select-String -Path $console -Pattern 'VERDICT' | Select-Object -Last 1
  Write-Host "$id $($verdict.Line)"
  $synced = $verdict -and $verdict.Line -match 'mismatches=0' -and $verdict.Line -match 'crash=False'

  & $python (Join-Path $here 'replay_sets.py') check $golden $id (Join-Path $work "$run.sets") $spec
  if (-not ($synced -and $LASTEXITCODE -eq 0)) { $allPassed = $false }
}
if ($allPassed) { exit 0 }
exit 1
