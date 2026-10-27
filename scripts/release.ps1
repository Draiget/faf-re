<#
.SYNOPSIS
  Builds release packages of the engine (x64, x86 or both) and zips them for upload.

.DESCRIPTION
  Builds the clang-cl Release preset of each architecture through build.ps1 (-NoCopy, so the
  FAF run folders are left alone), stages each package and zips it:

    <OutDir>\<version>\faf-engine-<version>-<arch>\     the unzipped package
    <OutDir>\<version>\faf-engine-<version>-<arch>.zip  the archive to upload
    <OutDir>\<version>\SHA256SUMS.txt                   checksums of every archive

  A package holds the exe (main_x64.exe / main.exe), its .pdb, the DXC runtime
  (dxcompiler.dll, dxil.dll), the fafengine\ hook folder and an INSTALL.txt for that
  architecture. FFmpeg is linked into the exe, so no FFmpeg DLLs ship.

  The version defaults to `git describe --tags --always --dirty` (e.g. v1.1.1-43-ge4cc5d8b0).
  Archive entries use forward slashes, so the zips unpack the same with Windows Explorer,
  7-Zip and unzip.

.EXAMPLE
  .\scripts\release.ps1                          # x64 + x86, versioned from git
.EXAMPLE
  .\scripts\release.ps1 -Arch x64 -Version v1.2.0
.EXAMPLE
  .\scripts\release.ps1 -NoBuild -SeparateSymbols   # package the last build; .pdb in its own zip
#>
[CmdletBinding()]
param(
  # x64, x86, or both (default).
  [ValidateSet('x64', 'x86', 'both')]
  [string]$Arch = 'both',

  # Version in the package names (default: git describe --tags --always --dirty).
  [string]$Version,

  # Where the release folders go (default: <repo>\out\release).
  [string]$OutDir,

  # Package the last Release build instead of building.
  [switch]$NoBuild,

  # Configure from scratch (cmake --fresh) and rebuild everything.
  [switch]$Rebuild,

  # Parallel compile jobs (default: CMake's choice).
  [int]$Jobs,

  # Stage the packages only; do not create the zips.
  [switch]$NoZip,

  # Put the .pdb into a separate faf-engine-<version>-<arch>-symbols.zip instead of the package.
  [switch]$SeparateSymbols
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent

$targets = @{
  x64 = @{ Preset = 'clang-x64-release'; Exe = 'main_x64'; RunDir = 'bin_x64'; Machine = 0x8664 }
  x86 = @{ Preset = 'clang-x86-release'; Exe = 'main';     RunDir = 'bin';     Machine = 0x014C }
}
$archs = if ($Arch -eq 'both') { @('x64', 'x86') } else { @($Arch) }

function Invoke-Git([string[]]$gitArgs) {
  $ErrorActionPreference = 'Continue'
  $out = & git -C $repo @gitArgs 2>$null
  if ($LASTEXITCODE -ne 0) { return $null }
  return "$out".Trim()
}

# The PE header's Machine field, to catch an exe of the wrong architecture in a build folder.
function Get-PeMachine([string]$path) {
  $fs = [IO.File]::OpenRead($path)
  try {
    $reader = New-Object IO.BinaryReader($fs)
    $fs.Position = 0x3C
    $fs.Position = $reader.ReadInt32() + 4
    return $reader.ReadUInt16()
  }
  finally { $fs.Dispose() }
}

function Get-InstallText([string]$a, [hashtable]$t) {
  $exe = "$($t.Exe).exe"
  $log = "C:\ProgramData\FAForever\logs\$($t.Exe).log"
  $lines = @(
    "FAF engine $Version ($a), built $(Get-Date -Format 'yyyy-MM-dd')",
    '',
    'Needs an installed FAF client (it creates C:\ProgramData\FAForever with bin\, gamedata\ and',
    'fa_path.lua) and Forged Alliance itself.',
    '',
    'What is in this package',
    ("  $exe".PadRight(28) + 'the engine'),
    ("  $($t.Exe).pdb".PadRight(28) + 'debug symbols; optional, but crash reports are much more useful with them'),
    '  dxcompiler.dll, dxil.dll  shader compiler for Direct3D 12 and Vulkan',
    '  fafengine\lua\...         the engine''s own Lua hook files; must sit in a folder named fafengine',
    '                            next to the exe (the engine mounts it at /fafengine)',
    '',
    'Install'
  )
  if ($a -eq 'x64') {
    $lines += @(
      '  1. Create C:\ProgramData\FAForever\bin_x64 (it must be next to FAF''s bin folder:',
      '     init_faf.lua finds fa_path.lua one folder up).',
      '  2. Copy these from C:\ProgramData\FAForever\bin into bin_x64:',
      '     init_faf.lua, SupComDataPath.lua, SupComDataPathFAF.lua, tahoma.ttf, tahomabd.ttf',
      '     (and any other init_*.lua you use).',
      '  3. Unzip this package into bin_x64, keeping the fafengine folder as is.'
    )
  }
  else {
    $lines += @(
      '  1. Unzip this package into C:\ProgramData\FAForever\bin (next to ForgedAlliance.exe;',
      '     keep ForgedAlliance.exe, it is still what the FAF client launches).'
    )
  }
  $lines += @(
    '',
    "Run, from C:\ProgramData\FAForever\$($t.RunDir):",
    "  $exe /init init_faf.lua /nobugreport /log $log",
    '',
    'Crash reports are written next to the exe as faf_crash_<date>.txt; please attach them',
    'together with the log file from /log.'
  )
  return ($lines -join "`r`n") + "`r`n"
}

function New-Zip([string]$zipPath, [IO.FileInfo[]]$files, [string]$root) {
  if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
  $root = $root.TrimEnd('\') + '\'
  $zip = [IO.Compression.ZipFile]::Open($zipPath, 'Create')
  try {
    foreach ($f in $files | Sort-Object FullName) {
      # Forward slashes: Windows PowerShell's Compress-Archive writes '\', which other
      # unzippers turn into file names instead of folders.
      $entry = $f.FullName.Substring($root.Length).Replace('\', '/')
      [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $f.FullName, $entry, 'Optimal')
    }
  }
  finally { $zip.Dispose() }
}

if (-not $Version) {
  $Version = Invoke-Git @('describe', '--tags', '--always', '--dirty')
  if (-not $Version) { throw 'git describe failed; pass -Version.' }
}
if ($Version -match '[\\/:*?"<>|\s]') { throw "-Version '$Version' is not usable in a file name." }
if ($Version -like '*-dirty') {
  Write-Warning "The working tree has uncommitted changes; the packages are named $Version."
}
if (-not $OutDir) { $OutDir = Join-Path $repo 'out\release' }
$releaseDir = Join-Path $OutDir $Version

if (-not $NoBuild) {
  $buildArgs = @{ Arch = $Arch; Configuration = 'Release'; NoCopy = $true }
  if ($Rebuild) { $buildArgs.Rebuild = $true }
  if ($Jobs -gt 0) { $buildArgs.Jobs = $Jobs }
  & (Join-Path $repo 'build.ps1') @buildArgs
}

Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null
$headTime = Invoke-Git @('log', '-1', '--format=%cI', 'HEAD')
$archives = @()

foreach ($a in $archs) {
  $t = $targets[$a]
  $buildDir = Join-Path $repo "build\$($t.Preset)\src"
  $exe = Join-Path $buildDir "$($t.Exe).exe"
  if (-not (Test-Path $exe)) { throw "$exe not found; build it first (drop -NoBuild)." }
  if ((Get-PeMachine $exe) -ne $t.Machine) { throw "$exe is not an $a executable." }
  if ($NoBuild -and $headTime -and (Get-Item $exe).LastWriteTime -lt [DateTime]::Parse($headTime)) {
    Write-Warning "$exe is older than the HEAD commit; it may not be a build of $Version."
  }

  $name = "faf-engine-$Version-$a"
  $stage = Join-Path $releaseDir $name
  Write-Host "== Staging $name" -ForegroundColor Cyan
  if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
  New-Item -ItemType Directory -Force -Path $stage | Out-Null

  $pdb = Join-Path $buildDir "$($t.Exe).pdb"
  if (-not (Test-Path $pdb)) { throw "$pdb not found." }
  Copy-Item $exe, $pdb $stage
  foreach ($dll in 'dxcompiler.dll', 'dxil.dll') {
    $path = Join-Path $buildDir $dll
    if (-not (Test-Path $path)) { throw "$path not found; the build stages it next to the exe." }
    Copy-Item $path $stage
  }
  # From data\, not the build folder: the build's copy_directory never deletes, so files
  # removed from data\fafengine linger in older build folders.
  Copy-Item (Join-Path $repo 'data\fafengine') $stage -Recurse
  Get-ChildItem $stage -Recurse -Directory -Filter '__pycache__' | Remove-Item -Recurse -Force
  [IO.File]::WriteAllText((Join-Path $stage 'INSTALL.txt'), (Get-InstallText $a $t))

  if ($NoZip) { continue }
  $all = Get-ChildItem $stage -Recurse -File
  $pdbFile = $all | Where-Object { $_.Name -eq "$($t.Exe).pdb" }
  if ($SeparateSymbols) {
    $zipPath = Join-Path $releaseDir "$name-symbols.zip"
    New-Zip $zipPath @($pdbFile) $stage
    $archives += $zipPath
    $all = $all | Where-Object { $_.FullName -ne $pdbFile.FullName }
  }
  $zipPath = Join-Path $releaseDir "$name.zip"
  New-Zip $zipPath $all $stage
  $archives += $zipPath
}

if ($archives.Count -gt 0) {
  # Checksums of every archive in the release folder, including ones from an earlier run
  # for the other architecture.
  $sums = Get-ChildItem $releaseDir -Filter '*.zip' | Sort-Object Name | ForEach-Object {
    "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower())  $($_.Name)"
  }
  [IO.File]::WriteAllText((Join-Path $releaseDir 'SHA256SUMS.txt'), (($sums -join "`n") + "`n"))
}

Write-Host ''
Write-Host "Release $Version -> $releaseDir" -ForegroundColor Green
foreach ($z in $archives) {
  Write-Host ("  {0,-48} {1,8:N1} MB" -f (Split-Path $z -Leaf), ((Get-Item $z).Length / 1MB))
}
if ($archives.Count -gt 0) { Write-Host '  SHA256SUMS.txt' }
