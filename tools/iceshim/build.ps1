# Builds tools/iceshim/out/faf-ice-adapter.jar, the launch shim (issue #231).
#
#   .\tools\iceshim\build.ps1 [-Jdk <folder with bin\javac.exe>]
#
# The default JDK is the FAF client's bundled runtime, which ships javac. The
# jar targets Java 17 so any runtime the client bundles can load it.
param([string]$Jdk = 'C:\Program Files\FAF Client\jre')

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$out = Join-Path $here 'out'
$classes = Join-Path $out 'classes'
if (Test-Path $classes) { Remove-Item -Recurse -Force $classes }
New-Item -ItemType Directory -Force $classes | Out-Null

& (Join-Path $Jdk 'bin\javac.exe') --release 17 -d $classes (Join-Path $here 'src\com\faforever\iceadapter\IceAdapter.java')
if ($LASTEXITCODE -ne 0) { throw "javac failed ($LASTEXITCODE)" }

$manifest = Join-Path $out 'MANIFEST.MF'
Set-Content -Encoding ascii -Path $manifest -Value "Manifest-Version: 1.0`r`nMain-Class: com.faforever.iceadapter.IceAdapter`r`n"
$jar = Join-Path $out 'faf-ice-adapter.jar'
& (Join-Path $Jdk 'bin\jar.exe') --create --file $jar --manifest $manifest -C $classes .
if ($LASTEXITCODE -ne 0) { throw "jar failed ($LASTEXITCODE)" }
Write-Host "built $jar"
