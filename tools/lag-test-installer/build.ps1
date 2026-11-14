param([string]$OutputPath)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$output = if ($OutputPath) { [IO.Path]::GetFullPath($OutputPath) } else { Join-Path $root 'out/Microchip faf-re builder V1.exe' }
New-Item -ItemType Directory -Path (Split-Path $output) -Force | Out-Null
$compiler = Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
$arguments = @('/nologo', '/target:winexe', '/platform:x64', '/optimize+', '/reference:System.Windows.Forms.dll', '/reference:System.Drawing.dll', '/reference:System.Web.Extensions.dll', '/reference:System.Core.dll', "/out:$output", "/win32manifest:$PSScriptRoot/app.manifest", "/resource:$PSScriptRoot/Build-FafRe.ps1,worker.ps1")
foreach ($name in @('lobby.lua', 'connectiontest.lua', 'connectionscore.lua')) {
    $arguments += "/resource:$root/data/fafengine/lua/ui/lobby/$name,$name"
}
$arguments += "/resource:$root/data/fafengine/lua/options/options.lua,options.lua"
$arguments += "/win32icon:$PSScriptRoot/assets/builder.ico"
& $compiler @arguments (Join-Path $PSScriptRoot 'Installer.cs') (Join-Path $PSScriptRoot 'BuilderTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Builder compilation failed.' }
& "$env:WINDIR/System32/WindowsPowerShell/v1.0/powershell.exe" -NoProfile -File (Join-Path $PSScriptRoot 'Test-Worker.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Download worker tests failed.' }
foreach ($test in @('--verify', '--selftest')) {
    $check = Start-Process -FilePath $output -ArgumentList $test -Wait -PassThru -WindowStyle Hidden
    if ($check.ExitCode -ne 0) { throw "Builder test $test failed: $($check.ExitCode)" }
}
Get-FileHash -Algorithm SHA256 $output
