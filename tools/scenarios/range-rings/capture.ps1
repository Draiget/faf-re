<#
.SYNOPSIS
  Screenshots for tools/scenarios/1p-rangerings-main.yaml: waits for the run's game log, and at
  every "RINGTEST SHOT <name>" line saves the game window as <run dir>\<name>.png. Stops at
  "RINGTEST DONE" or after -TimeoutSeconds.

.EXAMPLE
  # in one shell, from tools\
  powershell -File scenarios\range-rings\capture.ps1
  # in another
  .\bin\mpemu.exe run scenarios\1p-rangerings-main.yaml
#>
param(
  [string]$RunsDir = (Join-Path $PSScriptRoot '..\..\runs'),
  [string]$ScenarioName = '1p-rangerings-main',
  [string]$ProcessName = 'main_x64_rings',
  [int]$TimeoutSeconds = 420
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class RingCapture {
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
  $rect = New-Object RingCapture+RECT
  [void][RingCapture]::GetClientRect($proc.MainWindowHandle, [ref]$rect)
  $bmp = New-Object System.Drawing.Bitmap ([Math]::Max(1, $rect.Right)), ([Math]::Max(1, $rect.Bottom))
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $hdc = $g.GetHdc()
  # PW_CLIENTONLY | PW_RENDERFULLCONTENT: the client area, including flip-model swap chains.
  $ok = [RingCapture]::PrintWindow($proc.MainWindowHandle, $hdc, 3)
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
    if ($line -match 'RINGTEST SHOT (\S+)') { Save-Window (Join-Path (Split-Path $log) "$($Matches[1]).png") }
    elseif ($line -match 'RINGTEST') { Write-Host $line.Trim() }
    if ($line -match 'RINGTEST DONE') { break }
  }
}
finally { $reader.Dispose() }
