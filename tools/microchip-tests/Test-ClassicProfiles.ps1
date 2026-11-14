$ErrorActionPreference='Stop'
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$testRoot=Join-Path $repo ('.tmp/classic-profile-test-'+[guid]::NewGuid().ToString('N'))
$prefs=Join-Path $env:LOCALAPPDATA 'Gas Powered Games/Supreme Commander Forged Alliance/Game.prefs'
$before=(Get-FileHash $prefs).Hash
try {
    & (Join-Path $PSScriptRoot 'Run-Classic-Test.ps1') -Players 12 -Seconds 60 -Compare -GenerateOnly -RunPath $testRoot | Out-Null
    $classic=Get-Content (Join-Path $testRoot '12-player-classic-control.yaml') -Raw | ConvertFrom-Json
    $mixed=Get-Content (Join-Path $testRoot '12-player-mixed-x64.yaml') -Raw | ConvertFrom-Json
    if($classic.players.Count -ne 12 -or @($classic.players | Where-Object exe).Count -ne 0){throw 'Control must contain twelve classic engines.'}
    if($mixed.players.Count -ne 12 -or @($mixed.players | Where-Object exe).Count -ne 1 -or $mixed.players[-1].exe -notlike '*bin_x64*main_x64.exe'){throw 'Mixed test must contain exactly one x64 engine.'}
    if($mixed.players[0].exe -or $mixed.steps[1].host -ne 1){throw 'The host must use classic FAF.'}
    $joins=@($mixed.steps | Where-Object join)
    if($joins.Count -ne 11 -or $joins[-1].join -ne 12){throw 'Classic peers must join before the x64 seat.'}
    if($mixed.mode -ne 'direct' -or $mixed.hub){throw 'Test must be local direct mode.'}
    if(($mixed.players[-1].args -join ' ') -match 'RunWithTheWind|/d3d9|net_CheckOrderStreams|net_MaxSendRate'){throw 'Default test must not enable diagnostic probes.'}
    & (Join-Path $PSScriptRoot 'Run-Classic-Test.ps1') -Players 12 -Seconds 60 -GenerateOnly -X64DrainProbe -X64LegacyAckProbe -X64SendRate 8192 -X64Renderer d3d9 -RunPath $testRoot | Out-Null
    $probe=Get-Content (Join-Path $testRoot '12-player-mixed-x64.yaml') -Raw | ConvertFrom-Json
    if($probe.players[-1].args[1] -notmatch 'wld_RunWithTheWind=1' -or $probe.players[-1].args[-1] -ne '/d3d9'){throw 'Diagnostic probes must apply to the x64 seat only.'}
    if($probe.players[-1].args[1] -notmatch 'net_CheckOrderStreams=0' -or $probe.players[-1].args[1] -notmatch 'net_MaxSendRate=8192'){throw 'Network probes were not applied.'}
    $private=Get-Content (Join-Path $testRoot 'test-template.prefs') -Raw
    if($private -notmatch 'microchip_network_diagnostics = false' -or $private -notmatch 'microchip_client_test_recording = true'){throw 'Private logging preferences are wrong.'}
    if((Get-FileHash $prefs).Hash -ne $before){throw 'Normal game preferences were modified.'}
    Write-Host 'Classic-client profile checks passed.'
} finally {
    $resolved=[IO.Path]::GetFullPath($testRoot)
    $allowed=[IO.Path]::GetFullPath((Join-Path $repo '.tmp'))+[IO.Path]::DirectorySeparatorChar
    if($resolved.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase) -and (Split-Path $resolved -Leaf) -like 'classic-profile-test-*'){
        if(Test-Path -LiteralPath $resolved){Remove-Item -LiteralPath $resolved -Recurse -Force}
    }
}
