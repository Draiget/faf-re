<#
  Coverage driver for the live tour (2026-11-09): posts mouse messages to the coverage game's deepest child window -
  moves across the view, right-clicks (orders for the selection), left-clicks (select, or the command-mode order),
  left-drags (box select) and wheel turns (zoom) - on a fixed cycle until the game exits. Never moves the real cursor
  or takes the foreground (posted messages only; SetCursorPos is denied on this account anyway).
#>
param([int]$TimeoutSeconds = 900)

$ErrorActionPreference = 'Stop'
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class CovDrive {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
  [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X, Y; }
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr hwnd, out RECT rect);
  [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr hwnd, ref POINT point);
  [DllImport("user32.dll")] public static extern bool ScreenToClient(IntPtr hwnd, ref POINT point);
  [DllImport("user32.dll")] public static extern IntPtr RealChildWindowFromPoint(IntPtr parent, POINT point);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr hwnd, uint msg, IntPtr w, IntPtr l);
  public static IntPtr Deepest(IntPtr top, int x, int y, out int cx, out int cy) {
    POINT screen; screen.X = x; screen.Y = y;
    ClientToScreen(top, ref screen);
    IntPtr current = top;
    for (int i = 0; i < 8; i++) {
      POINT local = screen;
      ScreenToClient(current, ref local);
      IntPtr child = RealChildWindowFromPoint(current, local);
      if (child == IntPtr.Zero || child == current) break;
      current = child;
    }
    POINT final = screen;
    ScreenToClient(current, ref final);
    cx = final.X; cy = final.Y;
    return current;
  }
}
'@
[void][CovDrive]::SetProcessDPIAware()
$WM_MOUSEMOVE = 0x0200; $WM_LBUTTONDOWN = 0x0201; $WM_LBUTTONUP = 0x0202
$WM_RBUTTONDOWN = 0x0204; $WM_RBUTTONUP = 0x0205; $WM_MOUSEWHEEL = 0x020A; $MK_LBUTTON = 1; $MK_RBUTTON = 2

function Lparam([int]$x, [int]$y) { return [IntPtr](($y -shl 16) -bor ($x -band 0xFFFF)) }

function Get-Game {
  $procs = Get-CimInstance Win32_Process -Filter "CommandLine LIKE '%init_tour_live%' AND Name LIKE 'covclient%'" -ErrorAction SilentlyContinue
  foreach ($p in $procs) {
    $proc = Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue
    if ($proc -and $proc.MainWindowHandle -ne 0) { return $proc }
  }
  return $null
}

function Post([IntPtr]$top, [int]$x, [int]$y, [uint32]$msg, [int]$w) {
  $cx = 0; $cy = 0
  $target = [CovDrive]::Deepest($top, $x, $y, [ref]$cx, [ref]$cy)
  [void][CovDrive]::PostMessage($target, $msg, [IntPtr]$w, (Lparam $cx $cy))
}

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$seen = $false
$step = 0
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Milliseconds 700
  $proc = Get-Game
  if (-not $proc) { if ($seen) { Write-Host "game gone after $step steps"; break } else { continue } }
  $seen = $true
  $top = $proc.MainWindowHandle
  $rect = New-Object CovDrive+RECT
  [void][CovDrive]::GetClientRect($top, [ref]$rect)
  $w = $rect.Right; $h = $rect.Bottom
  if ($w -lt 200 -or $h -lt 200) { continue }
  # A fixed walk over the middle of the view (the panels sit at the edges).
  $fx = @(0.5, 0.42, 0.58, 0.47, 0.53, 0.38, 0.62)[$step % 7]
  $fy = @(0.5, 0.44, 0.56, 0.52, 0.47, 0.6, 0.4)[$step % 7]
  $x = [int]($w * $fx); $y = [int]($h * $fy)
  Post $top $x $y $WM_MOUSEMOVE 0
  switch ($step % 6) {
    0 { Post $top $x $y $WM_RBUTTONDOWN $MK_RBUTTON; Start-Sleep -Milliseconds 60; Post $top $x $y $WM_RBUTTONUP 0 }
    1 { Post $top $x $y $WM_LBUTTONDOWN $MK_LBUTTON; Start-Sleep -Milliseconds 60; Post $top $x $y $WM_LBUTTONUP 0 }
    2 {
      $x2 = [int]($w * 0.66); $y2 = [int]($h * 0.64)
      Post $top ([int]($w * 0.34)) ([int]($h * 0.36)) $WM_LBUTTONDOWN $MK_LBUTTON
      foreach ($k in 1..5) {
        $mx = [int]($w * 0.34 + ($x2 - $w * 0.34) * $k / 5); $my = [int]($h * 0.36 + ($y2 - $h * 0.36) * $k / 5)
        Post $top $mx $my $WM_MOUSEMOVE $MK_LBUTTON; Start-Sleep -Milliseconds 40
      }
      Post $top $x2 $y2 $WM_LBUTTONUP 0
    }
    3 { Post $top $x $y $WM_MOUSEWHEEL ((-120) -shl 16) }
    4 { Post $top $x $y $WM_MOUSEWHEEL (120 -shl 16) }
    5 { Post $top $x $y $WM_RBUTTONDOWN $MK_RBUTTON; Start-Sleep -Milliseconds 60; Post $top $x $y $WM_RBUTTONUP 0 }
  }
  $step++
}
Write-Host "driver done, $step steps"
