<#
.SYNOPSIS
  Builds the engine (main.exe / main_x64.exe) and copies it into the FAF run folders.

.DESCRIPTION
  x64 goes to <FafDir>\bin_x64 as main_x64.exe, x86 to <FafDir>\bin as main.exe, each with
  its .pdb, the fafengine\ hook folder, the FFmpeg DLLs and the DXC DLLs (dxcompiler.dll,
  dxil.dll) that Direct3D 12 and Vulkan need. Visual Studio 2022 is found with vswhere.

.EXAMPLE
  .\build.ps1                       # x64 Release, copied to C:\ProgramData\FAForever\bin_x64
.EXAMPLE
  .\build.ps1 -Arch both            # x64 and x86
.EXAMPLE
  .\build.ps1 -Arch x86 -Name main_test    # x86, copied to bin\ as main_test.exe
.EXAMPLE
  .\build.ps1 -NoBuild              # copy the last build only
#>
[CmdletBinding()]
param(
  # x64 (default), x86, or both.
  [ValidateSet('x64', 'x86', 'both')]
  [string]$Arch = 'x64',

  [ValidateSet('Release', 'Debug')]
  [string]$Configuration = 'Release',

  # Exe name in the run folder, without .exe (default main_x64 / main). Use another name to
  # keep the current build alongside, e.g. -Name main_x64_test. With -Arch both it gets a
  # _x86 suffix for the x86 copy unless it already differs per architecture.
  [string]$Name,

  # FAF data folder that holds bin\ and bin_x64\.
  [string]$FafDir = 'C:\ProgramData\FAForever',

  # Also copy the build into out\<arch>\ (the test-build folder).
  [switch]$Out,

  # Skip the build and only copy the last build output.
  [switch]$NoBuild,

  # Build only; do not copy anything.
  [switch]$NoCopy,

  # Rebuild instead of an incremental build.
  [switch]$Rebuild
)

$ErrorActionPreference = 'Stop'
$repo = $PSScriptRoot
$project = Join-Path $repo 'src\main.vcxproj'

$targets = @{
  x64 = @{ Platform = 'x64';   VcArch = 'x64';       Exe = 'main_x64'; RunDir = 'bin_x64'; DllArch = 'x64' }
  x86 = @{ Platform = 'Win32'; VcArch = 'amd64_x86'; Exe = 'main';     RunDir = 'bin';     DllArch = 'x86' }
}
$archs = if ($Arch -eq 'both') { @('x64', 'x86') } else { @($Arch) }

function Find-VcVarsAll {
  $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
  if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found; install Visual Studio 2022 with the C++ desktop workload." }
  $vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
  if (-not $vs) { throw "No Visual Studio with the C++ x86/x64 tools was found." }
  $vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvarsall.bat'
  if (-not (Test-Path $vcvars)) { throw "vcvarsall.bat not found under $vs." }
  return $vcvars
}

# Runs msbuild inside the vcvarsall environment for one architecture, without leaving that
# environment behind in the calling PowerShell session.
function Invoke-MsBuild([hashtable]$t) {
  $saved = Get-ChildItem env: | ForEach-Object { @{ Name = $_.Name; Value = $_.Value } }
  try {
    $env:FAF_VCVARS = Find-VcVarsAll
    $env:FAF_VCARCH = $t.VcArch
    $vars = cmd /s /c --% ""%FAF_VCVARS%" %FAF_VCARCH% >nul 2>nul && set"
    if ($LASTEXITCODE -ne 0) { throw "vcvarsall $($t.VcArch) failed." }
    foreach ($line in $vars) {
      $eq = $line.IndexOf('=')
      if ($eq -gt 0) { Set-Item -Path "env:$($line.Substring(0, $eq))" -Value $line.Substring($eq + 1) }
    }

    $msbuildTarget = if ($Rebuild) { 'Rebuild' } else { 'Build' }
    $msbuildArgs = @(
      $project, "/t:$msbuildTarget", "/p:Configuration=$Configuration", "/p:Platform=$($t.Platform)",
      '/m', '/v:minimal', '/nologo', '/p:FafStageToRunDir=false'
    )
    Write-Host "== Building $($t.Exe).exe ($Configuration|$($t.Platform))" -ForegroundColor Cyan
    & msbuild.exe @msbuildArgs
    if ($LASTEXITCODE -ne 0) {
      throw "Build failed for $($t.Platform) (msbuild exit $LASTEXITCODE). If it is LNK1201 (PDB in use), delete output\main\$($t.Platform)\$Configuration\$($t.Exe).pdb and build again."
    }
  }
  finally {
    Get-ChildItem env: | Where-Object { $n = $_.Name; -not ($saved | Where-Object { $_.Name -eq $n }) } |
      ForEach-Object { Remove-Item "env:$($_.Name)" }
    foreach ($v in $saved) { Set-Item -Path "env:$($v.Name)" -Value $v.Value }
  }
}

function Copy-Build([hashtable]$t, [string]$destDir, [string]$exeName) {
  $src = Join-Path $repo "output\main\$($t.Platform)\$Configuration"
  $exe = Join-Path $src "$($t.Exe).exe"
  if (-not (Test-Path $exe)) { throw "$exe not found; build it first (drop -NoBuild)." }
  New-Item -ItemType Directory -Force -Path $destDir | Out-Null

  $destExe = Join-Path $destDir "$exeName.exe"
  if (Test-Path $destExe) {
    # A running game keeps its exe locked; say so instead of failing halfway through the copy.
    try { [IO.File]::Open($destExe, 'Open', 'ReadWrite', 'None').Close() }
    catch { throw "$destExe is in use (is the game running?). Close it, or pass -Name <other> to copy beside it." }
  }

  Copy-Item $exe $destExe -Force
  $pdb = Join-Path $src "$($t.Exe).pdb"
  if (Test-Path $pdb) { Copy-Item $pdb (Join-Path $destDir "$exeName.pdb") -Force }

  $hooks = Join-Path $src 'fafengine'
  if (Test-Path $hooks) { Copy-Item $hooks $destDir -Recurse -Force }

  # Runtime DLLs: FFmpeg (staged next to the exe by the build) and DXC for D3D12/Vulkan.
  $dlls = @(Get-ChildItem $src -Filter '*.dll' -File)
  $dxc = Join-Path $repo "dependencies\dxc\bin\$($t.DllArch)"
  foreach ($n in 'dxcompiler.dll', 'dxil.dll') {
    $p = Join-Path $dxc $n
    if (Test-Path $p) { $dlls += Get-Item $p } else { Write-Warning "$p is missing; D3D12 and Vulkan will not start." }
  }
  foreach ($dll in $dlls) {
    $target = Join-Path $destDir $dll.Name
    # A DLL a running game holds open is the same file; skip it rather than fail.
    if ((Test-Path $target) -and (Get-Item $target).Length -eq $dll.Length -and
        (Get-Item $target).LastWriteTimeUtc -ge $dll.LastWriteTimeUtc) { continue }
    Copy-Item $dll.FullName $target -Force
  }
  Write-Host "   -> $destExe" -ForegroundColor Green
}

foreach ($a in $archs) {
  $t = $targets[$a]
  if (-not $NoBuild) { Invoke-MsBuild $t }
  if ($NoCopy) { continue }

  $exeName = $t.Exe
  if ($Name) {
    $exeName = $Name
    if ($archs.Count -gt 1 -and $a -eq 'x86') { $exeName = "${Name}_x86" }
  }
  Copy-Build $t (Join-Path $FafDir $t.RunDir) $exeName
  if ($Out) { Copy-Build $t (Join-Path $repo "out\$a") $t.Exe }
}

Write-Host ''
foreach ($a in $archs) {
  $t = $targets[$a]
  if ($NoCopy) { break }
  $exeName = if ($Name) { if ($archs.Count -gt 1 -and $a -eq 'x86') { "${Name}_x86" } else { $Name } } else { $t.Exe }
  Write-Host "Run ($a):" -ForegroundColor Cyan
  Write-Host "  cd $(Join-Path $FafDir $t.RunDir)"
  Write-Host "  .\$exeName.exe /init init_faf.lua /nobugreport /log $(Join-Path $FafDir "logs\$exeName.log")"
}
