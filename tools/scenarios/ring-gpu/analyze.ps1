<#
.SYNOPSIS
  Summarises a tools/scenarios/1p-ringgpu-* run: the mean "pass Ranges" CPU/GPU ms and draws for
  each "RINGGPU perf <scene>-<setting>" window, over all rounds (the first profile line of each
  window is skipped, it straddles the switch), and for each screenshot the pixels that differ from the same scene's
  `legacy` shot, or from -ReferenceRun's shot of the same name. The pause/speed cluster and the chat line, which
  animate while paused, are left out of the pixel counts.

.EXAMPLE
  powershell -File scenarios\ring-gpu\analyze.ps1 -Run runs\20261029-120000-1p-ringgpu-main
  powershell -File scenarios\ring-gpu\analyze.ps1 -Run <new run> -ReferenceRun <baseline exe run>
#>
param(
  [Parameter(Mandatory)] [string]$Run,
  [string]$ReferenceRun
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type -ReferencedAssemblies System.Drawing @'
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
public static class RingGpuDiff {
  // The two UI areas that animate while paused, as fractions of the client area: the pause/speed
  // cluster at the top right and the chat line ("Paused the game") at the left. Left out, so the
  // counts are the world's.
  static bool Animated(int x, int y, int w, int h) {
    double fx = (double)x / w, fy = (double)y / h;
    return (fx >= 0.64 && fx <= 0.87 && fy <= 0.13) || (fx >= 0.03 && fx <= 0.35 && fy >= 0.68 && fy <= 0.78);
  }
  // Returns { differing pixels, largest channel difference }.
  public static int[] Compare(string a, string b) {
    using (var x = new Bitmap(a)) using (var y = new Bitmap(b)) {
      if (x.Width != y.Width || x.Height != y.Height) return new[] { -1, -1 };
      var r = new Rectangle(0, 0, x.Width, x.Height);
      var dx = x.LockBits(r, ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
      var dy = y.LockBits(r, ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
      int n = dx.Stride * x.Height;
      var bx = new byte[n]; var by = new byte[n];
      Marshal.Copy(dx.Scan0, bx, 0, n); Marshal.Copy(dy.Scan0, by, 0, n);
      x.UnlockBits(dx); y.UnlockBits(dy);
      int differ = 0, worst = 0;
      for (int i = 0; i < n; i += 4) {
        int p = i / 4;
        if (Animated(p % x.Width, p / x.Width, x.Width, x.Height)) continue;
        int d = 0;
        for (int c = 0; c < 3; ++c) d = Math.Max(d, Math.Abs(bx[i + c] - by[i + c]));
        if (d > 0) { ++differ; worst = Math.Max(worst, d); }
      }
      return new[] { differ, worst };
    }
  }
}
'@

$log = Join-Path $Run 'game-1.log'
$rows = [ordered]@{}
$tag = $null
$skip = $false
foreach ($line in Get-Content $log) {
  if ($line -match 'RINGGPU perf (\S+)') {
    $tag = $Matches[1]; $skip = $true
    if ($tag -ne 'end') { if (-not $rows.Contains($tag)) { $rows[$tag] = New-Object System.Collections.ArrayList } }
    else { $tag = $null }
    continue
  }
  if ($line -match 'RINGGPU SHOT') { $tag = $null; continue }
  if ($tag -and $line -match 'pass Ranges\s+[\d.]+ calls\s+CPU\s+([\d.]+) ms\s+GPU\s+([\d.]+) ms per frame,\s+([\d.]+) draws') {
    if ($skip) { $skip = $false; continue }
    [void]$rows[$tag].Add([pscustomobject]@{ Cpu = [double]$Matches[1]; Gpu = [double]$Matches[2]; Draws = [double]$Matches[3] })
  }
}

$out = foreach ($key in $rows.Keys) {
  $samples = $rows[$key]
  $shot = Join-Path $Run "$key.png"
  $scene = $key -replace '-(legacy|gpu|cull|gpucull)$', ''
  $legacy = Join-Path $Run "$scene-legacy.png"
  $vsLegacy = if ((Test-Path $shot) -and (Test-Path $legacy)) { [RingGpuDiff]::Compare($legacy, $shot) } else { $null }
  $vsRef = $null
  if ($ReferenceRun) {
    $ref = Join-Path $ReferenceRun "$key.png"
    if ((Test-Path $shot) -and (Test-Path $ref)) { $vsRef = [RingGpuDiff]::Compare($ref, $shot) }
  }
  [pscustomobject]@{
    Window      = $key
    Samples     = $samples.Count
    'CPU ms'    = if ($samples.Count) { '{0:N3}' -f ($samples | Measure-Object Cpu -Average).Average } else { '' }
    'GPU ms'    = if ($samples.Count) { '{0:N3}' -f ($samples | Measure-Object Gpu -Average).Average } else { '' }
    Draws       = if ($samples.Count) { '{0:N1}' -f ($samples | Measure-Object Draws -Average).Average } else { '' }
    'px vs legacy' = if ($vsLegacy) { "$($vsLegacy[0]) (max $($vsLegacy[1]))" } else { '' }
    'px vs ref'    = if ($vsRef) { "$($vsRef[0]) (max $($vsRef[1]))" } else { '' }
  }
}
$out | Format-Table -AutoSize | Out-String -Width 220
