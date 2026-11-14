[CmdletBinding()]
param([string]$EngineDirectory = "$env:ProgramData/FAForever/bin_x64")
$ErrorActionPreference = 'Stop'
if (Get-Process main_x64,ForgedAlliance -ErrorAction SilentlyContinue) { throw 'Close the game before installing.' }
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$built = Join-Path $repo 'build/clang-x64-release/src'
$translatorHome = Join-Path $env:LOCALAPPDATA 'Microchip/faf-translator'
foreach ($file in @("$built/main_x64.exe", "$translatorHome/worker.py", "$translatorHome/python/Scripts/python.exe", "$EngineDirectory/main_x64.exe")) {
    if (-not (Test-Path -LiteralPath $file)) { throw "Required file missing: $file" }
}
$prefs = Join-Path $env:LOCALAPPDATA 'Gas Powered Games/Supreme Commander Forged Alliance/Game.prefs'
$text = [IO.File]::ReadAllText($prefs)
$uid = '02eeb8d2-e873-4dba-88cc-78756b16d2e5'
if ($text -notmatch '(?m)^active_mods\s*=\s*\{') { throw 'Could not locate the enabled mods list.' }
$backup = Join-Path $EngineDirectory ('lag-test-backups/offline-chat-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $backup -Force | Out-Null
Copy-Item $prefs (Join-Path $backup 'Game.prefs')
$files = @{
    'main_x64.exe' = "$built/main_x64.exe"
    'main_x64.pdb' = "$built/main_x64.pdb"
    'fafengine/lua/ui/translation.lua' = "$repo/data/fafengine/lua/ui/translation.lua"
    'fafengine/lua/ui/lobby/lobby.lua' = "$repo/data/fafengine/lua/ui/lobby/lobby.lua"
}
$encoding = New-Object Text.UTF8Encoding($false)
$runtimeConfig = Join-Path $EngineDirectory 'offline-translator.ini'
if (Test-Path -LiteralPath $runtimeConfig) { Copy-Item -LiteralPath $runtimeConfig -Destination (Join-Path $backup 'offline-translator.ini') }
[IO.File]::WriteAllText($runtimeConfig, "[runtime]`r`nhome=$translatorHome`r`n", [Text.Encoding]::Unicode)
foreach ($relative in $files.Keys) {
    $target = Join-Path $EngineDirectory $relative
    $saved = Join-Path $backup $relative
    New-Item -ItemType Directory -Path (Split-Path $saved) -Force | Out-Null
    New-Item -ItemType Directory -Path (Split-Path $target) -Force | Out-Null
    if (Test-Path -LiteralPath $target) { Copy-Item -LiteralPath $target -Destination $saved }
    $staged = $target + '.microchip-new'
    Copy-Item -LiteralPath $files[$relative] -Destination $staged -Force
    if ($relative -eq 'fafengine/lua/ui/lobby/lobby.lua' -and (Test-Path -LiteralPath $target)) {
        $old = [IO.File]::ReadAllText($target)
        $workers = [regex]::Match($old, 'local microchipSimWorkers = (nil|[0-9]+)')
        if ($workers.Success) {
            $hook = [IO.File]::ReadAllText($staged).Replace('local microchipSimWorkers = nil', $workers.Value)
            [IO.File]::WriteAllText($staged, $hook, $encoding)
        }
    }
    if (Test-Path -LiteralPath $target) { [IO.File]::Replace($staged, $target, ($saved + '.replaced')) }
    else { Move-Item -LiteralPath $staged -Destination $target }
}
$mods = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'My Games/Gas Powered Games/Supreme Commander Forged Alliance/Mods'
$mod = Join-Path $mods 'Microchip-Offline-Chat'
if (Test-Path -LiteralPath $mod) { Copy-Item -LiteralPath $mod -Destination (Join-Path $backup 'Microchip-Offline-Chat') -Recurse }
Copy-Item -LiteralPath "$repo/mods/Microchip-Offline-Chat" -Destination $mods -Recurse -Force
$escaped = [regex]::Escape($uid)
if ($text -match "\['$escaped'\]\s*=\s*(true|false)") {
    $text = [regex]::Replace($text, "\['$escaped'\]\s*=\s*(true|false)", "['$uid'] = true")
} else {
    $text = [regex]::Replace($text, '(?m)^active_mods\s*=\s*\{', "active_mods = {`r`n    ['$uid'] = true,")
}
[IO.File]::WriteAllText($prefs, $text, $encoding)
$metadataPath = Join-Path $EngineDirectory 'microchip-install.json'
if (Test-Path -LiteralPath $metadataPath) {
    Copy-Item -LiteralPath $metadataPath -Destination (Join-Path $backup 'microchip-install.json')
    $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
    $revision = (& git -C $repo rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Could not record installed source revision.' }
    $metadata | Add-Member -NotePropertyName customRevision -NotePropertyValue $revision -Force
    $metadata | Add-Member -NotePropertyName offlineTranslationVersion -NotePropertyValue 1 -Force
    [IO.File]::WriteAllText($metadataPath, ($metadata | ConvertTo-Json -Depth 8), $encoding)
}
Write-Output "Offline chat translation installed and enabled. Backup: $backup"
