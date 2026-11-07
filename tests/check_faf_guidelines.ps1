# tests/check_faf_guidelines.ps1
# Static dialect and rule checker against FAF_MODDING_AI_GUIDE.md

$files = Get-ChildItem -Recurse 'I:\FaforeverFiles\mods\TransportDropGhosts' -Filter '*.lua'
$foundIssues = @()

foreach ($f in $files) {
    $lines = Get-Content $f.FullName
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        $lineNum = $i + 1
        
        # Check length operator #
        if ($line -match '(^|[^-])#[A-Za-z_(]') {
            $foundIssues += "$($f.Name):$lineNum [Length operator #]: $line"
        }
        # Check modulo operator %
        if ($line -match '[A-Za-z0-9_)]\s*%\s*[A-Za-z0-9_(]') {
            $foundIssues += "$($f.Name):$lineNum [Modulo %]: $line"
        }
        # Check select / goto / math.fmod / table.unpack / GetSessionInfo
        if ($line -match '\b(goto|select|string\.gmatch|math\.fmod|GetSessionInfo)\b') {
            $foundIssues += "$($f.Name):$lineNum [Prohibited keyword]: $line"
        }
        # Check GetSurfaceHeight
        if ($line -match '\bGetSurfaceHeight\b') {
            $foundIssues += "$($f.Name):$lineNum [Sim-only GetSurfaceHeight in UI]: $line"
        }
        # Check direct _G. without rawget/rawset
        if ($line -match '_G\.[A-Za-z0-9_]+') {
            $foundIssues += "$($f.Name):$lineNum [Direct _G field access]: $line"
        }
        # Check top-level return in gamemain.lua hook
        if ($f.Name -eq 'gamemain.lua' -and $line -match '^return\s+') {
            $foundIssues += "$($f.Name):$lineNum [Top-level return in hook file]: $line"
        }
    }
}

if ($foundIssues.Count -eq 0) {
    Write-Host 'ALL STATIC AUDIT CHECKS PASSED: 0 violations found!' -ForegroundColor Green
    exit 0
} else {
    Write-Host "FOUND $($foundIssues.Count) ISSUES:" -ForegroundColor Red
    $foundIssues | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    exit 1
}
