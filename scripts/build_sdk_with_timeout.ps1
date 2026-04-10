param(
  [string]$Solution = "faf.sln",
  [string]$Target = "sdk",
  [string]$Configuration = "Debug",
  [string]$Platform = "x86",
  [int]$TimeoutMinutes = 120,
  [int]$NoOutputTimeoutMinutes = 10,
  [int]$HeartbeatSeconds = 30,
  [int]$PollSeconds = 2,
  [int]$MaxCpuCount = 1,
  [string]$LogPath = "msbuild_sdk_timeout.log",
  [string]$VcVarsBat = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsamd64_x86.bat"
)

$ErrorActionPreference = "Stop"

if ($TimeoutMinutes -lt 1) {
  throw "TimeoutMinutes must be >= 1."
}

if ($NoOutputTimeoutMinutes -lt 0) {
  throw "NoOutputTimeoutMinutes must be >= 0. Use 0 to disable no-output timeout."
}

if ($PollSeconds -lt 1) {
  throw "PollSeconds must be >= 1."
}

if ($HeartbeatSeconds -lt 0) {
  throw "HeartbeatSeconds must be >= 0. Use 0 to disable heartbeat output."
}

if ($MaxCpuCount -lt 1) {
  throw "MaxCpuCount must be >= 1."
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$solutionPath = if ([IO.Path]::IsPathRooted($Solution)) { $Solution } else { Join-Path $repoRoot $Solution }
$logFilePath = if ([IO.Path]::IsPathRooted($LogPath)) { $LogPath } else { Join-Path $repoRoot $LogPath }

if (-not (Test-Path -LiteralPath $solutionPath)) {
  throw "Solution not found: $solutionPath"
}

if (-not (Test-Path -LiteralPath $VcVarsBat)) {
  throw "VC vars script not found: $VcVarsBat"
}

$msbuildArgs = @(
  "`"$solutionPath`"",
  "/t:$Target",
  "/p:Configuration=$Configuration",
  "/p:Platform=$Platform",
  "/m:$MaxCpuCount",
  "/nr:false",
  "/nodeReuse:false"
) -join " "

$logDirectory = Split-Path -Parent $logFilePath
if (-not [string]::IsNullOrWhiteSpace($logDirectory)) {
  New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
}

$tempDirectory = Join-Path $env:TEMP "faf-msbuild-timeout"
New-Item -ItemType Directory -Path $tempDirectory -Force | Out-Null

$jobId = [Guid]::NewGuid().ToString("N")
$batchPath = Join-Path $tempDirectory "run_$jobId.cmd"
$stdoutPath = Join-Path $tempDirectory "run_$jobId.stdout.log"
$stderrPath = Join-Path $tempDirectory "run_$jobId.stderr.log"

$batchContent = @"
@echo off
call "$VcVarsBat"
if errorlevel 1 exit /b %errorlevel%
msbuild $msbuildArgs
exit /b %errorlevel%
"@

Set-Content -LiteralPath $batchPath -Value $batchContent -Encoding Ascii

function Get-FileLength([string]$PathValue) {
  if (-not (Test-Path -LiteralPath $PathValue)) {
    return 0
  }
  return (Get-Item -LiteralPath $PathValue).Length
}

function Merge-BuildLogs {
  if (Test-Path -LiteralPath $logFilePath) {
    Remove-Item -LiteralPath $logFilePath -Force
  }

  if (Test-Path -LiteralPath $stdoutPath) {
    Get-Content -LiteralPath $stdoutPath | Set-Content -LiteralPath $logFilePath
  }

  if (Test-Path -LiteralPath $stderrPath) {
    if (Test-Path -LiteralPath $logFilePath) {
      Add-Content -LiteralPath $logFilePath -Value ""
      Add-Content -LiteralPath $logFilePath -Value "===== STDERR ====="
      Add-Content -LiteralPath $logFilePath -Value ""
    }
    Get-Content -LiteralPath $stderrPath | Add-Content -LiteralPath $logFilePath
  }
}

function Stop-BuildProcessTree([int]$RootPid, [datetime]$BuildStartTime) {
  & taskkill /PID $RootPid /T /F | Out-Null
  Start-Sleep -Seconds 1

  foreach ($name in @("cl", "c1xx", "link", "msbuild", "mspdbsrv", "cvtres", "rc")) {
    Get-Process -Name $name -ErrorAction SilentlyContinue |
      Where-Object {
        try {
          $_.StartTime -ge $BuildStartTime
        } catch {
          $false
        }
      } |
      Stop-Process -Force -ErrorAction SilentlyContinue
  }
}

function Get-BuildProcesses([datetime]$BuildStartTime) {
  $result = @()
  foreach ($name in @("cl", "c1xx", "link", "msbuild", "mspdbsrv", "cvtres", "rc")) {
    $result += Get-Process -Name $name -ErrorAction SilentlyContinue |
      Where-Object {
        try {
          $_.StartTime -ge $BuildStartTime
        } catch {
          $false
        }
      }
  }
  return $result
}

Write-Host "Running build with timeouts"
Write-Host "  Total timeout: $TimeoutMinutes minute(s)"
if ($NoOutputTimeoutMinutes -gt 0) {
  Write-Host "  No-activity timeout: $NoOutputTimeoutMinutes minute(s) (output or compiler CPU progress)"
} else {
  Write-Host "  No-activity timeout: disabled"
}
if ($HeartbeatSeconds -gt 0) {
  Write-Host "  Heartbeat: every $HeartbeatSeconds second(s)"
} else {
  Write-Host "  Heartbeat: disabled"
}
Write-Host "Command: msbuild $solutionPath /t:$Target /p:Configuration=$Configuration /p:Platform=$Platform /m:$MaxCpuCount /nr:false /nodeReuse:false"
Write-Host "Log: $logFilePath"

$startTime = Get-Date
$absoluteTimeoutAt = $startTime.AddMinutes($TimeoutMinutes)
$proc = Start-Process `
  -FilePath "cmd.exe" `
  -ArgumentList "/c `"$batchPath`"" `
  -WorkingDirectory $repoRoot `
  -PassThru `
  -RedirectStandardOutput $stdoutPath `
  -RedirectStandardError $stderrPath

$lastStdoutLength = Get-FileLength $stdoutPath
$lastStderrLength = Get-FileLength $stderrPath
$lastOutputAt = Get-Date
$lastActivityAt = $lastOutputAt
$lastCpuSeconds = 0.0
$lastHeartbeatAt = $startTime
$timeoutReason = ""

while (-not $proc.HasExited) {
  Start-Sleep -Seconds $PollSeconds

  $now = Get-Date
  $stdoutLength = Get-FileLength $stdoutPath
  $stderrLength = Get-FileLength $stderrPath
  if (($stdoutLength -ne $lastStdoutLength) -or ($stderrLength -ne $lastStderrLength)) {
    $lastStdoutLength = $stdoutLength
    $lastStderrLength = $stderrLength
    $lastOutputAt = $now
    $lastActivityAt = $now
  }

  $buildProcesses = Get-BuildProcesses -BuildStartTime $startTime
  $cpuSeconds = 0.0
  if ($buildProcesses.Count -gt 0) {
    $cpuMeasure = $buildProcesses | Measure-Object -Property CPU -Sum
    if ($null -ne $cpuMeasure.Sum) {
      $cpuSeconds = [double]$cpuMeasure.Sum
    }
  }

  if ($cpuSeconds -gt ($lastCpuSeconds + 0.01)) {
    $lastActivityAt = $now
  }
  $lastCpuSeconds = $cpuSeconds

  if (($HeartbeatSeconds -gt 0) -and ($now -ge $lastHeartbeatAt.AddSeconds($HeartbeatSeconds))) {
    $elapsedMinutes = [Math]::Round(($now - $startTime).TotalMinutes, 1)
    $idleMinutes = [Math]::Round(($now - $lastActivityAt).TotalMinutes, 1)
    $sinceOutputMinutes = [Math]::Round(($now - $lastOutputAt).TotalMinutes, 1)
    Write-Host ("[heartbeat] elapsed={0}m idle={1}m since-output={2}m active-procs={3} cpu-seconds={4:N1}" -f `
      $elapsedMinutes, `
      $idleMinutes, `
      $sinceOutputMinutes, `
      $buildProcesses.Count, `
      $cpuSeconds)
    $lastHeartbeatAt = $now
  }

  if ($now -ge $absoluteTimeoutAt) {
    $timeoutReason = "total"
    break
  }
  if (($NoOutputTimeoutMinutes -gt 0) -and ($now -ge $lastActivityAt.AddMinutes($NoOutputTimeoutMinutes))) {
    $timeoutReason = "no_activity"
    break
  }
}

if (-not [string]::IsNullOrWhiteSpace($timeoutReason)) {
  if ($timeoutReason -eq "no_activity") {
    Write-Warning "Build produced no activity for $NoOutputTimeoutMinutes minute(s). Killing process tree for PID $($proc.Id)..."
  } else {
    Write-Warning "Build exceeded total timeout ($TimeoutMinutes minute(s)). Killing process tree for PID $($proc.Id)..."
  }

  Stop-BuildProcessTree -RootPid $proc.Id -BuildStartTime $startTime
  $proc.WaitForExit(5000) | Out-Null

  Merge-BuildLogs
  Remove-Item -LiteralPath $batchPath, $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue

  Write-Host "Timed out. See log: $logFilePath"
  exit 124
}

$proc.WaitForExit() | Out-Null
Merge-BuildLogs
Remove-Item -LiteralPath $batchPath, $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue

$exitCode = $proc.ExitCode
$reportedErrorCount = $null
if (Test-Path -LiteralPath $logFilePath) {
  $summaryMatches = Select-String -Path $logFilePath -Pattern '^\s*(\d+)\s+Error\(s\)\s*$'
  if ($summaryMatches.Count -gt 0) {
    $lastSummary = $summaryMatches[$summaryMatches.Count - 1]
    if ($lastSummary.Matches.Count -gt 0) {
      $reportedErrorCount = [int]$lastSummary.Matches[0].Groups[1].Value
    }
  }
}

if ($null -ne $reportedErrorCount) {
  $exitCode = if ($reportedErrorCount -eq 0) { 0 } else { 1 }
} elseif ($null -eq $exitCode) {
  $exitCode = 1
}
Write-Host "Build finished with exit code: $exitCode"
Write-Host "Log: $logFilePath"
exit $exitCode
