[CmdletBinding()]
param(
    [string]$WxRoot = "",
    [string]$PatchFile = "",
    [string]$VcVarsBat = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsamd64_x86.bat",
    [switch]$SkipPatch,
    [switch]$PatchOnly,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

function Require-Path([string]$PathValue, [string]$Label) {
    if (-not (Test-Path -LiteralPath $PathValue)) {
        throw "$Label not found: $PathValue"
    }
}

$scriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptRoot)) {
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}

if ([string]::IsNullOrWhiteSpace($PatchFile)) {
    $PatchFile = Join-Path $scriptRoot "..\\dependencies\\patches\\wxwindows_2_4_2_faf_required.patch"
}

if ([string]::IsNullOrWhiteSpace($WxRoot)) {
    $WxRoot = $env:WX_ROOT
}
if ([string]::IsNullOrWhiteSpace($WxRoot)) {
    throw "wx root is required. Pass -WxRoot <external-wx-path> or set WX_ROOT."
}

$wxRootResolved = (Resolve-Path -LiteralPath $WxRoot).Path
$patchFileResolved = (Resolve-Path -LiteralPath $PatchFile).Path
$vcVarsResolved = (Resolve-Path -LiteralPath $VcVarsBat).Path
$mswDir = Join-Path $wxRootResolved "src\\msw"
$libDir = Join-Path $wxRootResolved "lib"

Require-Path -PathValue $wxRootResolved -Label "wx root"
Require-Path -PathValue $patchFileResolved -Label "Patch file"
Require-Path -PathValue $vcVarsResolved -Label "VS developer environment script"
Require-Path -PathValue $mswDir -Label "wx MSW source directory"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "git is required to apply the wx patch."
}

if (-not $SkipPatch) {
    & git -C $wxRootResolved apply --reverse --check $patchFileResolved *> $null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[wx] Patch already applied."
    } else {
        & git -C $wxRootResolved apply --check $patchFileResolved
        if ($LASTEXITCODE -ne 0) {
            throw "Patch does not apply cleanly to $wxRootResolved."
        }
        & git -C $wxRootResolved apply $patchFileResolved
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to apply patch: $patchFileResolved"
        }
        Write-Host "[wx] Patch applied."
    }
} else {
    Write-Host "[wx] Patch step skipped."
}

if ($PatchOnly) {
    Write-Host "[wx] Patch-only mode requested. Build step skipped."
    return
}

$buildCommands = @(
    "call `"$vcVarsResolved`" >nul",
    "set `"WXWIN=$wxRootResolved`"",
    "cd /d `"$mswDir`""
)

if ($Clean) {
    $buildCommands += "nmake /f makefile.vc clean FINAL=1 DLL=0 WXMAKINGDLL= CRTFLAG=/MD"
}

$buildCommands += "nmake /f makefile.vc FINAL=1 DLL=0 WXMAKINGDLL= CRTFLAG=/MD"
$buildCommand = ($buildCommands -join " && ")

& cmd.exe /c $buildCommand
if ($LASTEXITCODE -ne 0) {
    throw "wx build failed with exit code $LASTEXITCODE."
}

$requiredLibs = @(
    "png.lib",
    "zlib.lib",
    "jpeg.lib",
    "tiff.lib",
    "regex.lib",
    "wxmsw.lib"
)

$missingLibs = @()
foreach ($lib in $requiredLibs) {
    $libPath = Join-Path $libDir $lib
    if (-not (Test-Path -LiteralPath $libPath)) {
        $missingLibs += $lib
    }
}

if ($missingLibs.Count -gt 0) {
    throw "Build finished but required libs are missing under ${libDir}: $($missingLibs -join ', ')"
}

Write-Host "[wx] Ready. Required libs are available under $libDir"
