<#
.SYNOPSIS
  Builds the engine (main.exe / main_x64.exe) with the CMake presets and copies it into the
  FAF run folders.

.DESCRIPTION
  Configures (first run, or after a CMake change) and builds the clang-cl preset for each
  architecture. Configure fetches and patches every dependency (cmake/FafDependencies.cmake),
  FFmpeg included, so a fresh clone needs nothing else than the tools listed in README.md.

  x64 goes to <FafDir>\bin_x64 as main_x64.exe, x86 to <FafDir>\bin as main.exe, each with
  its .pdb, the fafengine\ hook folder and the DXC DLLs (dxcompiler.dll, dxil.dll) that
  Direct3D 12 and Vulkan need. The build output stays in build\<preset>\src.

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

  # Configure from scratch (cmake --fresh) and rebuild everything.
  [switch]$Rebuild,

  # Parallel compile jobs (default: CMake's choice, one per logical CPU).
  [int]$Jobs
)

$ErrorActionPreference = 'Stop'
$repo = $PSScriptRoot

$targets = @{
  x64 = @{ Preset = "clang-x64-$($Configuration.ToLower())"; Exe = 'main_x64'; RunDir = 'bin_x64' }
  x86 = @{ Preset = "clang-x86-$($Configuration.ToLower())"; Exe = 'main';     RunDir = 'bin' }
}
$archs = if ($Arch -eq 'both') { @('x64', 'x86') } else { @($Arch) }

# cmake and ninja from PATH, else the copies Visual Studio 2022 ships with its CMake support.
function Find-CMake {
  $onPath = Get-Command cmake -ErrorAction SilentlyContinue
  if ($onPath) { return $onPath.Source }
  $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
  if (Test-Path $vswhere) {
    $vs = & $vswhere -latest -products '*' -property installationPath
    $bundled = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake'
    $exe = Join-Path $bundled 'CMake\bin\cmake.exe'
    if ($vs -and (Test-Path $exe)) {
      if (-not (Get-Command ninja -ErrorAction SilentlyContinue)) { $env:PATH = "$(Join-Path $bundled 'Ninja');$env:PATH" }
      return $exe
    }
  }
  throw "cmake not found: put CMake 3.25+ and Ninja on PATH, or install Visual Studio 2022 with 'C++ CMake tools for Windows'."
}

function Invoke-CMake([string[]]$cmakeArgs) {
  # CMake prints warnings on stderr; with 'Stop', Windows PowerShell would turn the first
  # one into a terminating error when output is redirected. Only the exit code counts.
  $ErrorActionPreference = 'Continue'
  & $script:cmake @cmakeArgs
  if ($LASTEXITCODE -ne 0) { throw "cmake $($cmakeArgs -join ' ') failed (exit $LASTEXITCODE)." }
}

function Invoke-Build([hashtable]$t) {
  if (-not $script:cmake) { $script:cmake = Find-CMake }
  Push-Location $repo
  try {
    $cache = Join-Path $repo "build\$($t.Preset)\CMakeCache.txt"
    Write-Host "== Configuring $($t.Preset)" -ForegroundColor Cyan
    if ($Rebuild) { Invoke-CMake @('--preset', $t.Preset, '--fresh') }
    elseif (-not (Test-Path $cache)) { Invoke-CMake @('--preset', $t.Preset) }

    Write-Host "== Building $($t.Exe).exe ($($t.Preset))" -ForegroundColor Cyan
    $buildArgs = @('--build', '--preset', $t.Preset)
    if ($Jobs -gt 0) { $buildArgs += @('-j', "$Jobs") }
    Invoke-CMake $buildArgs
  }
  finally { Pop-Location }
}

function Copy-Build([hashtable]$t, [string]$destDir, [string]$exeName) {
  $src = Join-Path $repo "build\$($t.Preset)\src"
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

  # The DXC runtime the build staged next to the exe (named, so leftovers of older
  # builds in the same folder are not copied along).
  foreach ($dll in @('dxcompiler.dll', 'dxil.dll' | ForEach-Object { Get-Item (Join-Path $src $_) -ErrorAction SilentlyContinue })) {
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
  if (-not $NoBuild) { Invoke-Build $t }
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
