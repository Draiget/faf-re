<#
.SYNOPSIS
  Driver for tools/scenarios/1p-uifix-main.yaml: waits for the run's game log and answers the UI
  hook's lines - "UITEST CURSOR x y" moves the cursor onto that client pixel, "UITEST RDRAG x1 y1
  x2 y2 name" right-drags between two client pixels and saves the window mid-drag, "UITEST SHOT
  name" saves the window as <run dir>\<name>.png. Stops at "UITEST DONE" or after -TimeoutSeconds.
  It moves the real cursor and brings the game window to the front.

.EXAMPLE
  # in one shell, from tools\
  powershell -File scenarios\ui-fixes\drive.ps1
  # in another
  .\bin\mpemu.exe run scenarios\1p-uifix-main.yaml
#>
param(
  [string]$RunsDir = (Join-Path $PSScriptRoot '..\..\runs'),
  [string]$ScenarioName = '1p-uifix-main',
  [string]$ProcessName = 'main_fixcheck',
  [int]$TimeoutSeconds = 420
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class UiDrive {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
  [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X, Y; }
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr hwnd, out RECT rect);
  [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr hwnd, ref POINT point);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr hdc, uint flags);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hwnd);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint flags, int dx, int dy, uint data, UIntPtr extra);
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint flags, UIntPtr extra);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern IntPtr WindowFromPoint(POINT point);
  [DllImport("user32.dll")] public static extern IntPtr GetAncestor(IntPtr hwnd, uint flags);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hwnd, int cmd);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr hwnd);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hwnd, IntPtr pid);
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint from, uint to, bool attach);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  public static void ForceForeground(IntPtr hwnd) {
    uint fg = GetWindowThreadProcessId(GetForegroundWindow(), IntPtr.Zero);
    uint me = GetCurrentThreadId();
    uint game = GetWindowThreadProcessId(hwnd, IntPtr.Zero);
    AttachThreadInput(me, fg, true);
    AttachThreadInput(game, fg, true);
    BringWindowToTop(hwnd);
    SetForegroundWindow(hwnd);
    AttachThreadInput(game, fg, false);
    AttachThreadInput(me, fg, false);
  }
}
'@

# Windows only lets a process take the foreground right after input; a tapped Alt counts.
function Set-GameForeground([IntPtr]$hwnd) {
  [UiDrive]::keybd_event(0x12, 0, 0, [UIntPtr]::Zero)
  [UiDrive]::keybd_event(0x12, 0, 2, [UIntPtr]::Zero)
  [void][UiDrive]::ShowWindow($hwnd, 5)
  [UiDrive]::ForceForeground($hwnd)
  Start-Sleep -Milliseconds 500
  Write-Host ("foreground is game: {0}" -f ([UiDrive]::GetForegroundWindow() -eq $hwnd))
}
$MOUSEEVENTF_RIGHTDOWN = 0x0008
$MOUSEEVENTF_RIGHTUP = 0x0010

$started = Get-Date
$deadline = $started.AddSeconds($TimeoutSeconds)

$log = $null
while (-not $log -and (Get-Date) -lt $deadline) {
  $dir = Get-ChildItem $RunsDir -Directory -Filter "*-$ScenarioName" -ErrorAction SilentlyContinue |
    Where-Object { $_.CreationTime -ge $started.AddSeconds(-5) } | Sort-Object CreationTime -Descending | Select-Object -First 1
  if ($dir -and (Test-Path (Join-Path $dir.FullName 'game-1.log'))) { $log = Join-Path $dir.FullName 'game-1.log' }
  else { Start-Sleep -Milliseconds 500 }
}
if (-not $log) { throw "no game log for $ScenarioName under $RunsDir" }
Write-Host "watching $log"

function Get-GameWindow {
  $proc = Get-Process $ProcessName -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
  if (-not $proc) { Write-Warning "no $ProcessName window"; return [IntPtr]::Zero }
  return $proc.MainWindowHandle
}

function Move-CursorToClient([IntPtr]$hwnd, [int]$x, [int]$y) {
  $point = New-Object UiDrive+POINT
  $point.X = $x; $point.Y = $y
  [void][UiDrive]::ClientToScreen($hwnd, [ref]$point)
  [void][UiDrive]::SetCursorPos($point.X, $point.Y)
  $under = [UiDrive]::GetAncestor([UiDrive]::WindowFromPoint($point), 2)
  if ($under -ne $hwnd) { Write-Host "cursor at $($point.X),$($point.Y) is over another window" }
}

function Save-Window([IntPtr]$hwnd, [string]$path) {
  if ($hwnd -eq [IntPtr]::Zero) { return }
  $rect = New-Object UiDrive+RECT
  [void][UiDrive]::GetClientRect($hwnd, [ref]$rect)
  $bmp = New-Object System.Drawing.Bitmap ([Math]::Max(1, $rect.Right)), ([Math]::Max(1, $rect.Bottom))
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $hdc = $g.GetHdc()
  # PW_CLIENTONLY | PW_RENDERFULLCONTENT: the client area, including flip-model swap chains.
  $ok = [UiDrive]::PrintWindow($hwnd, $hdc, 3)
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
    if ($line -notmatch 'UITEST') { continue }
    Write-Host ("[{0:HH:mm:ss.f}] {1}" -f (Get-Date), $line.Trim())
    $hwnd = Get-GameWindow
    if ($line -match 'UITEST CURSOR (-?\d+) (-?\d+)') {
      Set-GameForeground $hwnd
      # Two moves, so the game sees a mouse-move inside the view.
      Move-CursorToClient $hwnd ([int]$Matches[1] + 4) ([int]$Matches[2] + 4)
      Start-Sleep -Milliseconds 100
      Move-CursorToClient $hwnd ([int]$Matches[1]) ([int]$Matches[2])
    }
    elseif ($line -match 'UITEST RDRAG (-?\d+) (-?\d+) (-?\d+) (-?\d+) (\S+)') {
      $x1 = [int]$Matches[1]; $y1 = [int]$Matches[2]; $x2 = [int]$Matches[3]; $y2 = [int]$Matches[4]; $name = $Matches[5]
      Set-GameForeground $hwnd
      Move-CursorToClient $hwnd $x1 $y1
      Start-Sleep -Milliseconds 150
      [UiDrive]::mouse_event($MOUSEEVENTF_RIGHTDOWN, 0, 0, 0, [UIntPtr]::Zero)
      for ($i = 1; $i -le 20; $i++) {
        Move-CursorToClient $hwnd ([int]($x1 + ($x2 - $x1) * $i / 20)) ([int]($y1 + ($y2 - $y1) * $i / 20))
        Start-Sleep -Milliseconds 40
      }
      Start-Sleep -Milliseconds 1500
      Save-Window $hwnd (Join-Path (Split-Path $log) "$name.png")
      [UiDrive]::mouse_event($MOUSEEVENTF_RIGHTUP, 0, 0, 0, [UIntPtr]::Zero)
    }
    elseif ($line -match 'UITEST SHOT (\S+)') {
      Save-Window $hwnd (Join-Path (Split-Path $log) "$($Matches[1]).png")
    }
    if ($line -match 'UITEST DONE') { break }
  }
}
finally { $reader.Dispose() }
