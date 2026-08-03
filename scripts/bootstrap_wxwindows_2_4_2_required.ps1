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

# UNICODE=1 because the shipped engine linked a Unicode wxWidgets:
# wxApp::RegisterWindowClasses (0x00991E70) fills in a WNDCLASSW and calls
# RegisterClassW with wxChar* class names, and FUN_00848050 takes the
# const wchar_t* out of wxURL::GetProtocolName straight into wcsicmp. An ANSI
# build of the same source has matching class layouts but the wrong character
# type throughout, which showed up as a truncated window class name and title.
#
# /EHsc replaces the makefile's /GX-: the binary's wxTempFile::~wxTempFile has
# exception frames and a security cookie, which /GX- does not produce.
#
# This produces lib\wxmswu.lib and lib\mswu\wx\setup.h, leaving any previously
# built ANSI wxmsw.lib in place.
$unicodeFlags = 'UNICODE=1 "OVERRIDEFLAGS=/DUNICODE /D_UNICODE /EHsc"'

if ($Clean) {
    $buildCommands += "nmake /f makefile.vc clean FINAL=1 DLL=0 WXMAKINGDLL= CRTFLAG=/MD $unicodeFlags"
}

$buildCommands += "nmake /f makefile.vc FINAL=1 DLL=0 WXMAKINGDLL= CRTFLAG=/MD $unicodeFlags"
$buildCommand = ($buildCommands -join " && ")

& cmd.exe /c $buildCommand
if ($LASTEXITCODE -ne 0) {
    throw "wx build failed with exit code $LASTEXITCODE."
}

# makefile.vc only copies include\wx\msw\setup.h into the per-configuration
# directory, so the Unicode configuration's setup.h still says
# `wxUSE_UNICODE 0`. Left alone, the library is Unicode while everything that
# includes its headers sees wxChar as char.
$unicodeSetupHeader = Join-Path $libDir "mswu\wx\setup.h"
Require-Path -PathValue $unicodeSetupHeader -Label "Unicode setup.h"
$setupText = Get-Content -LiteralPath $unicodeSetupHeader -Raw
$ansiDefine = "#ifndef wxUSE_UNICODE`r`n    #define wxUSE_UNICODE 0`r`n#endif"
if ($setupText.Contains($ansiDefine)) {
    $setupText = $setupText.Replace($ansiDefine, "#ifndef wxUSE_UNICODE`r`n    #define wxUSE_UNICODE 1`r`n#endif")
    Set-Content -LiteralPath $unicodeSetupHeader -Value $setupText -Encoding utf8 -NoNewline
    Write-Host "[wx] Stamped wxUSE_UNICODE=1 into $unicodeSetupHeader"
} elseif ($setupText -notmatch "#define wxUSE_UNICODE 1") {
    throw "Could not stamp wxUSE_UNICODE=1 into $unicodeSetupHeader - check the template."
}

$requiredLibs = @(
    "png.lib",
    "zlib.lib",
    "jpeg.lib",
    "tiff.lib",
    "regex.lib",
    "wxmswu.lib"
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
