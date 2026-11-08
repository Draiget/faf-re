# tests/test_transport_log_audit.ps1
# Automated audit test for FAF runtime logs: ensures no Lua runtime errors, nonexistent global accesses, or unhandled exceptions.

param(
    [string]$LogPath = "C:\ProgramData\FAForever\logs\log64.txt"
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================"
Write-Host "Running Transport Log Audit Test"
Write-Host "Log file: $LogPath"
Write-Host "============================================================"

if (-not (Test-Path $LogPath)) {
    Write-Warning "Log file not found at $LogPath. (Game hasn't been run yet)."
    exit 0
}

$content = Get-Content -Path $LogPath -Encoding UTF8

$errors = @()
$inTraceback = $false
$currentError = @()

for ($i = 0; $i -lt $content.Count; $i++) {
    $line = $content[$i]

    if ($line -match "Error running.*gamemain\.lua" -or
        $line -match "access to nonexistent global variable" -or
        $line -match "transport_holograms\.lua.*error" -or
        $line -match "invalid effect technique requested" -or
        $line -match "unknown technique" -or
        $line -match "stack traceback:") {
        
        $start = [Math]::Max(0, $i - 2)
        $end = [Math]::Min($content.Count - 1, $i + 6)
        $snippet = ($content[$start..$end] -join "`n")
        $errors += $snippet
        $i += 5 # skip forward
    }
}

if ($errors.Count -gt 0) {
    Write-Error "Found $($errors.Count) Lua/Shader runtime errors in ${LogPath}:`n`n"
    foreach ($err in $errors) {
        Write-Host "------------------------------------------------------------" -ForegroundColor Red
        Write-Host $err -ForegroundColor Red
    }
    exit 1
}

Write-Host "No Lua or shader runtime errors found in ${LogPath}. Audit PASSED." -ForegroundColor Green
exit 0
