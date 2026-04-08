param(
  [string]$Solution = "faf.sln",
  [string]$Target = "sdk",
  [string]$Configuration = "Debug",
  [string]$Platform = "x86",
  [int]$TimeoutMinutes = 120,
  [int]$NoOutputTimeoutMinutes = 10,
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

Write-Host "Running build with timeouts"
Write-Host "  Total timeout: $TimeoutMinutes minute(s)"
if ($NoOutputTimeoutMinutes -gt 0) {
  Write-Host "  No-output timeout: $NoOutputTimeoutMinutes minute(s)"
} else {
  Write-Host "  No-output timeout: disabled"
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
$timeoutReason = ""

while (-not $proc.HasExited) {
  Start-Sleep -Seconds $PollSeconds

  $stdoutLength = Get-FileLength $stdoutPath
  $stderrLength = Get-FileLength $stderrPath
  if (($stdoutLength -ne $lastStdoutLength) -or ($stderrLength -ne $lastStderrLength)) {
    $lastStdoutLength = $stdoutLength
    $lastStderrLength = $stderrLength
    $lastOutputAt = Get-Date
  }

  $now = Get-Date
  if ($now -ge $absoluteTimeoutAt) {
    $timeoutReason = "total"
    break
  }
  if (($NoOutputTimeoutMinutes -gt 0) -and ($now -ge $lastOutputAt.AddMinutes($NoOutputTimeoutMinutes))) {
    $timeoutReason = "no_output"
    break
  }
}

if (-not [string]::IsNullOrWhiteSpace($timeoutReason)) {
  if ($timeoutReason -eq "no_output") {
    Write-Warning "Build produced no output for $NoOutputTimeoutMinutes minute(s). Killing process tree for PID $($proc.Id)..."
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
