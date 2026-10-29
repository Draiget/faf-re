<#
.SYNOPSIS
  Writes a diff picture of two screenshots of the same size: -Before dimmed to a third, every
  pixel that differs in red. Prints the differing pixel count, the largest channel difference
  and their bounding box.

.EXAMPLE
  powershell -File scenarios\ring-gpu\diffimage.ps1 -Before a.png -After b.png -Out diff.png
#>
param(
  [Parameter(Mandatory)] [string]$Before,
  [Parameter(Mandatory)] [string]$After,
  [Parameter(Mandatory)] [string]$Out
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type -ReferencedAssemblies System.Drawing @'
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
public static class RingGpuDiffImage {
  public static string Make(string a, string b, string outPath) {
    using (var x = new Bitmap(a)) using (var y = new Bitmap(b)) {
      if (x.Width != y.Width || x.Height != y.Height) return "sizes differ";
      var r = new Rectangle(0, 0, x.Width, x.Height);
      var dx = x.LockBits(r, ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
      var dy = y.LockBits(r, ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
      int n = dx.Stride * x.Height;
      var bx = new byte[n]; var by = new byte[n];
      Marshal.Copy(dx.Scan0, bx, 0, n); Marshal.Copy(dy.Scan0, by, 0, n);
      x.UnlockBits(dx); y.UnlockBits(dy);
      var o = new byte[n];
      int count = 0, worst = 0, minX = int.MaxValue, minY = int.MaxValue, maxX = -1, maxY = -1;
      for (int i = 0; i < n; i += 4) {
        int d = 0;
        for (int c = 0; c < 3; ++c) d = Math.Max(d, Math.Abs(bx[i + c] - by[i + c]));
        int p = i / 4, px = p % x.Width, py = p / x.Width;
        if (d > 0) {
          ++count; worst = Math.Max(worst, d);
          minX = Math.Min(minX, px); maxX = Math.Max(maxX, px); minY = Math.Min(minY, py); maxY = Math.Max(maxY, py);
          o[i] = 0; o[i + 1] = 0; o[i + 2] = 255; o[i + 3] = 255;
        } else {
          o[i] = (byte)(bx[i] / 3); o[i + 1] = (byte)(bx[i + 1] / 3); o[i + 2] = (byte)(bx[i + 2] / 3); o[i + 3] = 255;
        }
      }
      using (var z = new Bitmap(x.Width, x.Height, PixelFormat.Format32bppArgb)) {
        var dz = z.LockBits(r, ImageLockMode.WriteOnly, PixelFormat.Format32bppArgb);
        Marshal.Copy(o, 0, dz.Scan0, n);
        z.UnlockBits(dz);
        z.Save(outPath, ImageFormat.Png);
      }
      if (count == 0) return "0 px differ";
      return string.Format("{0} px differ (max {1}), box x {2}-{3} y {4}-{5}", count, worst, minX, maxX, minY, maxY);
    }
  }
}
'@
[RingGpuDiffImage]::Make((Resolve-Path $Before).Path, (Resolve-Path $After).Path, [IO.Path]::GetFullPath($Out))
