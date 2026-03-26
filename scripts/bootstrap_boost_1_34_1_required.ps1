[CmdletBinding()]
param(
    [string]$BoostRoot = "",
    [string]$PatchFile = "",
    [string]$StageName = "faf-required-md",
    [switch]$SkipPatch,
    [switch]$PatchOnly,
    [switch]$RebuildAll
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
    $PatchFile = Join-Path $scriptRoot "..\\dependencies\\patches\\boost_1_34_1_faf_required.patch"
}
if ([string]::IsNullOrWhiteSpace($BoostRoot)) {
    $BoostRoot = $env:BOOST_ROOT
}
if ([string]::IsNullOrWhiteSpace($BoostRoot)) {
    throw "Boost root is required. Pass -BoostRoot <external-boost-path> or set BOOST_ROOT."
}

$boostRootResolved = (Resolve-Path -LiteralPath $BoostRoot).Path
$patchFileResolved = (Resolve-Path -LiteralPath $PatchFile).Path
$bjamExe = Join-Path $boostRootResolved "tools\\jam\\src\\bin.ntx86\\bjam.exe"
$stageDir = Join-Path (Join-Path (Join-Path $boostRootResolved "stage") $StageName) "lib"

Require-Path -PathValue $boostRootResolved -Label "Boost root"
Require-Path -PathValue $patchFileResolved -Label "Patch file"
Require-Path -PathValue $bjamExe -Label "bjam executable"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "git is required to apply the Boost patch."
}

if (-not $SkipPatch) {
    & git -C $boostRootResolved apply --reverse --check $patchFileResolved *> $null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[boost] Patch already applied."
    } else {
        & git -C $boostRootResolved apply --check $patchFileResolved
        if ($LASTEXITCODE -ne 0) {
            throw "Patch does not apply cleanly to $boostRootResolved."
        }
        & git -C $boostRootResolved apply $patchFileResolved
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to apply patch: $patchFileResolved"
        }
        Write-Host "[boost] Patch applied."
    }
} else {
    Write-Host "[boost] Patch step skipped."
}

if ($PatchOnly) {
    Write-Host "[boost] Patch-only mode requested. Build step skipped."
    return
}

if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    Write-Warning "cl.exe not found in PATH. Run from a VS Developer shell if build fails."
}

$bjamArgs = @(
    "--v2",
    "--layout=tagged",
    "toolset=msvc",
    "threading=multi",
    "link=static",
    "runtime-link=shared",
    "--with-thread",
    "--with-filesystem",
    "stage",
    "--stagedir=stage/$StageName"
)

if ($RebuildAll) {
    $bjamArgs = @("-a") + $bjamArgs
}

Push-Location $boostRootResolved
try {
    & $bjamExe @bjamArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Boost build failed with exit code $LASTEXITCODE."
    }
} finally {
    Pop-Location
}

$requiredLibs = @(
    "libboost_thread-vc-mt-gd.lib",
    "libboost_thread-vc-mt.lib",
    "libboost_filesystem-vc-mt-gd.lib",
    "libboost_filesystem-vc-mt.lib"
)

$missingLibs = @()
foreach ($lib in $requiredLibs) {
    $libPath = Join-Path $stageDir $lib
    if (-not (Test-Path -LiteralPath $libPath)) {
        $missingLibs += $lib
    }
}

if ($missingLibs.Count -gt 0) {
    throw "Build finished but required libs are missing under ${stageDir}: $($missingLibs -join ', ')"
}

Write-Host "[boost] Ready. Required libs are available under $stageDir"
