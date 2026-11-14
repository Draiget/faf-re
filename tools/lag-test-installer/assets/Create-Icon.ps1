$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$frames = @()
foreach ($size in @(16, 24, 32, 48, 64, 128, 256)) {
    $bitmap = New-Object Drawing.Bitmap($size, $size)
    $g = [Drawing.Graphics]::FromImage($bitmap)
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear([Drawing.Color]::Transparent)
    $g.ScaleTransform(($size / 256.0), ($size / 256.0))
    $points = [Drawing.PointF[]]@(
        (New-Object Drawing.PointF(48,12)), (New-Object Drawing.PointF(208,12)),
        (New-Object Drawing.PointF(244,48)), (New-Object Drawing.PointF(244,208)),
        (New-Object Drawing.PointF(208,244)), (New-Object Drawing.PointF(48,244)),
        (New-Object Drawing.PointF(12,208)), (New-Object Drawing.PointF(12,48)))
    $fill = New-Object Drawing.Drawing2D.LinearGradientBrush((New-Object Drawing.Point(0,0)), (New-Object Drawing.Point(256,256)), ([Drawing.Color]::FromArgb(34,58,73)), ([Drawing.Color]::FromArgb(6,14,23)))
    $edge = New-Object Drawing.Pen(([Drawing.Color]::FromArgb(114,215,230)), 9)
    $g.FillPolygon($fill, $points); $g.DrawPolygon($edge, $points)
    $pins = New-Object Drawing.Pen(([Drawing.Color]::FromArgb(114,215,230)), 8)
    foreach ($position in @(90,128,166)) {
        $g.DrawLine($pins, $position, 42, $position, 66)
        $g.DrawLine($pins, $position, 190, $position, 214)
        $g.DrawLine($pins, 42, $position, 66, $position)
        $g.DrawLine($pins, 190, $position, 214, $position)
    }
    $g.FillRectangle($fill, 65,65,126,126)
    $g.DrawRectangle($pins, 65,65,126,126)
    $mark = [Drawing.PointF[]]@(
        (New-Object Drawing.PointF(88,164)), (New-Object Drawing.PointF(88,94)),
        (New-Object Drawing.PointF(108,94)), (New-Object Drawing.PointF(128,123)),
        (New-Object Drawing.PointF(148,94)), (New-Object Drawing.PointF(168,94)),
        (New-Object Drawing.PointF(168,164)), (New-Object Drawing.PointF(149,164)),
        (New-Object Drawing.PointF(149,124)), (New-Object Drawing.PointF(128,152)),
        (New-Object Drawing.PointF(107,124)), (New-Object Drawing.PointF(107,164)))
    $white = New-Object Drawing.SolidBrush(([Drawing.Color]::FromArgb(226,244,249)))
    $g.FillPolygon($white, $mark)
    $stream = New-Object IO.MemoryStream
    $bitmap.Save($stream, [Drawing.Imaging.ImageFormat]::Png)
    $frames += ,@{ Size=$size; Bytes=$stream.ToArray() }
    if ($size -eq 256) { $bitmap.Save((Join-Path $PSScriptRoot 'builder.png'), [Drawing.Imaging.ImageFormat]::Png) }
    $stream.Dispose(); $white.Dispose(); $pins.Dispose(); $edge.Dispose(); $fill.Dispose(); $g.Dispose(); $bitmap.Dispose()
}
$file = [IO.File]::Create((Join-Path $PSScriptRoot 'builder.ico'))
$writer = New-Object IO.BinaryWriter($file)
try {
    $writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]$frames.Count)
    $offset = 6 + 16 * $frames.Count
    foreach ($frame in $frames) {
        $dimension = if ($frame.Size -eq 256) { 0 } else { $frame.Size }
        $writer.Write([byte]$dimension); $writer.Write([byte]$dimension)
        $writer.Write([byte]0); $writer.Write([byte]0)
        $writer.Write([uint16]1); $writer.Write([uint16]32)
        $writer.Write([uint32]$frame.Bytes.Length); $writer.Write([uint32]$offset)
        $offset += $frame.Bytes.Length
    }
    foreach ($frame in $frames) { $writer.Write([byte[]]$frame.Bytes) }
} finally { $writer.Dispose(); $file.Dispose() }
