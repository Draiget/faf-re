<#
.SYNOPSIS
  Builds every app of the tools module (tools/cmd/<app>) into tools/bin, plus
  faf-pioneer's ICE adapter (bin/faf-adapter.exe) when its checkout is found.

.PARAMETER Pioneer
  faf-pioneer checkout; default is a sibling of faf-main (G:\projects\faf-pioneer).

.PARAMETER Debug
  Build without optimisations/inlining so Delve / GoLand / VS Code step cleanly.
#>
param(
    [string]$Pioneer = (Join-Path $PSScriptRoot '..\..\faf-pioneer'),
    [switch]$Debug
)
$ErrorActionPreference = 'Stop'
$bin = Join-Path $PSScriptRoot 'bin'
New-Item -ItemType Directory -Force $bin | Out-Null

$flags = @()
if ($Debug) { $flags += '-gcflags=all=-N -l' }

Push-Location $PSScriptRoot
try {
    foreach ($dir in Get-ChildItem (Join-Path $PSScriptRoot 'cmd') -Directory) {
        $app = $dir.Name
        & go build @flags -o (Join-Path $bin "$app.exe") "./cmd/$app"
        if ($LASTEXITCODE -ne 0) { throw "go build ./cmd/$app failed" }
        Write-Host "built bin\$app.exe"
    }
} finally { Pop-Location }

if (Test-Path (Join-Path $Pioneer 'cmd\faf-adapter')) {
    Push-Location $Pioneer
    try {
        & go build @flags -o (Join-Path $bin 'faf-adapter.exe') ./cmd/faf-adapter
        if ($LASTEXITCODE -ne 0) { throw 'go build faf-pioneer/cmd/faf-adapter failed' }
        Write-Host "built bin\faf-adapter.exe from $Pioneer"
    } finally { Pop-Location }
} else {
    Write-Warning "faf-pioneer not found at $Pioneer; mode ice needs -adapter <faf-adapter.exe>"
}
