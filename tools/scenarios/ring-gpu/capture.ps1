<#
.SYNOPSIS
  Screenshots for tools/scenarios/1p-ringgpu-*.yaml: waits for the run's game log, and at every
  "RINGGPU SHOT <name>" line saves the game window as <run dir>\<name>.png. Stops at
  "RINGGPU DONE" or after -TimeoutSeconds.

.EXAMPLE
  # in one shell, from tools\
  powershell -File scenarios\ring-gpu\capture.ps1 -ScenarioName 1p-ringgpu-d3d12 -ProcessName main_x64_ringgpu
  # in another
  .\bin\mpemu.exe run scenarios\1p-ringgpu-d3d12.yaml
#>
param(
  [string]$RunsDir = (Join-Path $PSScriptRoot '..\..\runs'),
  [Parameter(Mandatory)] [string]$ScenarioName,
  [Parameter(Mandatory)] [string]$ProcessName,
  [int]$TimeoutSeconds = 600
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class RingGpuCapture {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr hwnd, out RECT rect);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr hdc, uint flags);
}
'@

$started = Get-Date
$deadline = $started.AddSeconds($TimeoutSeconds)

# The run directory mpemu creates for this scenario after we started.
$log = $null
while (-not $log -and (Get-Date) -lt $deadline) {
  $dir = Get-ChildItem $RunsDir -Directory -Filter "*-$ScenarioName" -ErrorAction SilentlyContinue |
    Where-Object { $_.CreationTime -ge $started.AddSeconds(-5) } | Sort-Object CreationTime -Descending | Select-Object -First 1
  if ($dir -and (Test-Path (Join-Path $dir.FullName 'game-1.log'))) { $log = Join-Path $dir.FullName 'game-1.log' }
  else { Start-Sleep -Milliseconds 500 }
}
if (-not $log) { throw "no game log for $ScenarioName under $RunsDir" }
Write-Host "watching $log"

function Save-Window([string]$path) {
  $proc = Get-Process $ProcessName -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
  if (-not $proc) { Write-Warning "no $ProcessName window"; return }
  $rect = New-Object RingGpuCapture+RECT
  [void][RingGpuCapture]::GetClientRect($proc.MainWindowHandle, [ref]$rect)
  $bmp = New-Object System.Drawing.Bitmap ([Math]::Max(1, $rect.Right)), ([Math]::Max(1, $rect.Bottom))
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $hdc = $g.GetHdc()
  # PW_CLIENTONLY | PW_RENDERFULLCONTENT: the client area, including flip-model swap chains.
  $ok = [RingGpuCapture]::PrintWindow($proc.MainWindowHandle, $hdc, 3)
  $g.ReleaseHdc($hdc); $g.Dispose()
  $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
  Write-Host "$(if ($ok) { 'saved' } else { 'PrintWindow failed, saved anyway' }) $path"
}

$stream = [IO.File]::Open($log, 'Open', 'Read', 'ReadWrite')
$reader = New-Object IO.StreamReader($stream)
try {
  while ((Get-Date) -lt $deadline) {
    $line = $reader.ReadLine()
    if ($null -eq $line) { Start-Sleep -Milliseconds 200; continue }
    if ($line -match 'RINGGPU SHOT (\S+)') { Save-Window (Join-Path (Split-Path $log) "$($Matches[1]).png") }
    elseif ($line -match 'RINGGPU (spawned|engineers|DONE)') { Write-Host $line.Trim() }
    if ($line -match 'RINGGPU DONE') { break }
  }
}
finally { $reader.Dispose() }
