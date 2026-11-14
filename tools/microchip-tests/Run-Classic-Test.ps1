[CmdletBinding()]
param(
    [ValidateSet(2,4,6,8,12)][int]$Players = 2,
    [ValidateRange(20,1800)][int]$Seconds = 120,
    [switch]$Compare,
    [switch]$ClassicOnly,
    [switch]$GenerateOnly,
    [switch]$X64DrainProbe,
    [switch]$X64LegacyAckProbe,
    [ValidateRange(2048,65536)][int]$X64SendRate = 2048,
    [ValidateSet('auto','d3d9','d3d11','d3d12')][string]$X64Renderer = 'auto',
    [ValidateRange(1,10)][int]$JoinDelaySeconds = 2,
    [switch]$Pause,
    [string]$X64Exe,
    [string]$FafRoot = "$env:ProgramData\FAForever",
    [string]$RunPath
)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$classic = Join-Path $FafRoot 'bin/ForgedAlliance.exe'
$rebuilt = if($X64Exe){[IO.Path]::GetFullPath($X64Exe)}else{Join-Path $FafRoot 'bin_x64/main_x64.exe'}
$harness = Join-Path $repo 'tools/bin/mpemu.exe'
foreach($file in @($classic,$rebuilt,$harness)) { if(-not (Test-Path -LiteralPath $file)){throw "Required file missing: $file"} }
if(-not $GenerateOnly -and (Get-Process -Name ForgedAlliance,main_x64,main,mpemu -ErrorAction SilentlyContinue)) { throw 'Close your current game or previous test before starting a local test.' }
if(-not $RunPath) { $RunPath=Join-Path $repo ('tools/runs/microchip-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)) }
$RunPath=[IO.Path]::GetFullPath($RunPath)
New-Item -ItemType Directory -Path $RunPath -Force | Out-Null
$template=Join-Path $RunPath 'test-template.prefs'
$modUid='203f10b8-4547-4ae7-9483-77fa4c1cdb20'
$modName='Microchip-Client-Test'
$prefs=Join-Path $env:LOCALAPPDATA 'Gas Powered Games/Supreme Commander Forged Alliance/Game.prefs'
$text=[IO.File]::ReadAllText($prefs)
$active=[regex]::new('(?ms)^active_mods\s*=\s*\{.*?^\}')
$replacement="active_mods = {`r`n    ['$modUid'] = true,`r`n}"
if($active.IsMatch($text)) { $text=$active.Replace($text,$replacement,1) }
elseif($text -match '(?m)^active_mods\s*=') { throw 'Unsupported active_mods format in preferences.' }
else { $text+="`r`n$replacement`r`n" }
foreach($entry in @(@('microchip_network_diagnostics','false'),@('microchip_client_test_recording','true'))) {
    $pattern='(?m)^'+$entry[0]+'\s*=\s*(?:true|false)[^\r\n]*'
    $line=$entry[0]+' = '+$entry[1]
    if([regex]::IsMatch($text,$pattern)){ $text=[regex]::Replace($text,$pattern,$line) } else { $text=$line+"`r`n"+$text }
}
[IO.File]::WriteAllText($template,$text,(New-Object Text.UTF8Encoding($false)))
if(-not $GenerateOnly) {
    # Install a passive UI logger, enabled only in the private test preferences.
    $mods=Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'My Games/Gas Powered Games/Supreme Commander Forged Alliance/Mods'
    $target=Join-Path $mods $modName
    New-Item -ItemType Directory -Path "$target/hook/lua/ui/game","$target/modules" -Force | Out-Null
    [IO.File]::WriteAllText("$target/mod_info.lua", "name='Microchip Local Client Test Recorder'`nuid='$modUid'`nversion=1`nauthor='Microchip'`nui_only=true`nexclusive=false`nselectable=true`ndescription='Passive local-test logger; used with private test preferences.'`n",(New-Object Text.UTF8Encoding($false)))
    Copy-Item -LiteralPath (Join-Path $repo 'data/fafengine/lua/diagnostics/networkrecorder.lua') -Destination "$target/modules/networkrecorder.lua" -Force
    $hook=[IO.File]::ReadAllText((Join-Path $repo 'data/fafengine/lua/ui/game/gamemain.lua')).Replace('/fafengine/lua/diagnostics/networkrecorder.lua',"/mods/$modName/modules/networkrecorder.lua").Replace('microchip_network_diagnostics','microchip_client_test_recording')
    [IO.File]::WriteAllText("$target/hook/lua/ui/game/gamemain.lua",$hook,(New-Object Text.UTF8Encoding($false)))
}
function New-TestScenario([bool]$OnlyClassic) {
    $name=if($OnlyClassic){"$Players-player-classic-control"}else{"$Players-player-mixed-x64"}
    $seats=@()
    for($i=1;$i -le $Players;$i++) {
        $seat=[ordered]@{uid=$i;name=('Classic{0:d2}' -f $i);faction='uef';startSpot=$i}
        if(-not $OnlyClassic -and $i -eq $Players) {
            $seat.name='MicrochipX64'; $seat.exe=$rebuilt
            $seat.args=@('/con','lua_AllowPrecompiledChunks=1;ren_GpuSelectBrackets=0')
            if($X64DrainProbe){$seat.args[1]+=';wld_RunWithTheWind=1'}
            if($X64LegacyAckProbe){$seat.args[1]+=';net_CheckOrderStreams=0'}
            if($X64SendRate -ne 2048){$seat.args[1]+=';net_MaxSendRate='+[string]$X64SendRate}
            if($X64Renderer -ne 'auto'){$seat.args+=('/'+$X64Renderer)}
        }
        $seats+=,$seat
    }
    $steps=@(@{start='all'},@{host=1})
    for($i=2;$i -le $Players;$i++){
        $steps+=,@{join=$i}
        if($i -lt $Players){$steps+=,@{wait=([string]$JoinDelaySeconds+'s')}}
    }
    $steps+=@(@{waitState=@{uids='all';state='Launching';timeout='3m'}},@{note='All clients launched; first 20 seconds are warm-up.'},@{wait=([string]$Seconds+'s')})
    return [ordered]@{
        name=$name;description='Local real-engine clients. Classic host; x64 joins the other seats in mixed mode.'
        timeout=([string]($Seconds+420)+'s');mode='direct';lobby='auto';map='dualgap_adaptive.v0014'
        gameOptions=@{Victory='sandbox';GameSpeed='normal'}
        game=@{exe=$classic;init=(Join-Path $FafRoot 'bin/init.lua');nosound=$true;tile=$true;window=@{width=1024;height=768};prefs=$template;saveReplays=$true}
        players=$seats
        steps=$steps
        expect=@{allLaunched=$true;noDesync=$true;noCrash=$true}
    }
}
$modes=if($Compare){@($true,$false)}elseif($ClassicOnly){@($true)}else{@($false)}
$plan=@()
foreach($mode in $modes) {
    $scenario=New-TestScenario $mode
    $file=Join-Path $RunPath ($scenario.name+'.yaml')
    [IO.File]::WriteAllText($file,($scenario | ConvertTo-Json -Depth 12),(New-Object Text.UTF8Encoding($false)))
    $plan+=,[pscustomobject]@{Name=$scenario.name;Scenario=$file;RunDir=(Join-Path $RunPath $scenario.name)}
}
if($GenerateOnly) { $plan | Select-Object Name,Scenario; return }
Write-Host "Local test: $Players real game processes on this PC. Other players use classic FAF."
Write-Host 'This does not join public FAF or reproduce internet routing. Same-PC resource contention affects results.'
Write-Host 'Keep game windows visible. Ctrl+C stops the test and closes its clients.'
Write-Host "Results: $RunPath"
$results=@()
foreach($test in $plan) {
    Write-Host "Starting $($test.Name)..."
    $savedPreference=$ErrorActionPreference
    $previousTestHub=$env:MPEMU_HUB
    try {
        $env:MPEMU_HUB=$null
        $ErrorActionPreference='Continue'
        & $harness run $test.Scenario -run-dir $test.RunDir 2>&1 | Tee-Object -FilePath (Join-Path $RunPath ($test.Name+'-launcher.log'))
        $code=$LASTEXITCODE
    } finally { $ErrorActionPreference=$savedPreference; $env:MPEMU_HUB=$previousTestHub }
    $results+=,[pscustomobject]@{test=$test.Name;exitCode=$code;folder=$test.RunDir}
    if($code -ne 0) { Write-Warning 'The run failed; inspect its logs before interpreting performance.'; break }
}
$results | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $RunPath 'runs.json') -Encoding UTF8
$summary=@(); $missingSamples=$false
foreach($test in $plan) {
    $gameLogs=@(Get-ChildItem $test.RunDir -Filter 'game-*.log' -ErrorAction SilentlyContinue)
    if($gameLogs.Count -ne $Players){$missingSamples=$true; Write-Warning "Expected $Players game logs for $($test.Name), found $($gameLogs.Count)."}
    foreach($gameLog in $gameLogs) {
        $stream=[IO.File]::Open($gameLog.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        $reader=New-Object IO.StreamReader($stream)
        try { $samples=@(while($null -ne ($line=$reader.ReadLine())) {
            if($line -match 'MicrochipNetDiag SAMPLE wall=([0-9.]+).*?tick=([0-9.]+)') {
                [pscustomobject]@{wall=[double]::Parse($Matches[1],[Globalization.CultureInfo]::InvariantCulture);tick=[double]::Parse($Matches[2],[Globalization.CultureInfo]::InvariantCulture)}
            }
        }) } finally { $reader.Dispose(); $stream.Dispose() }
        $steady=@(); if($samples.Count){ $steady=@($samples | Where-Object {$_.wall -ge $samples[0].wall+20 -and $_.tick -gt 0}) }
        if($samples.Count -lt 3 -or $samples[-1].tick -le $samples[0].tick){$missingSamples=$true; Write-Warning "No verified simulation progress in $($gameLog.Name); this is not a valid performance result."}
        $tps=$null
        if($steady.Count -ge 2 -and $steady[-1].wall -gt $steady[0].wall){$tps=[math]::Round(($steady[-1].tick-$steady[0].tick)/($steady[-1].wall-$steady[0].wall),3)}
        $summary+=,[pscustomobject]@{test=$test.Name;client=$gameLog.BaseName;samples=$samples.Count;steadyTicksPerSecond=$tps;log=$gameLog.FullName}
    }
}
$summary | Export-Csv (Join-Path $RunPath 'performance.csv') -NoTypeInformation
$summary | Format-Table test,client,samples,steadyTicksPerSecond
Write-Host "Finished. Results and logs: $RunPath"
if($Pause){Read-Host 'Press Enter to close' | Out-Null}
if($missingSamples -or @($results | Where-Object exitCode -ne 0).Count){exit 1}
