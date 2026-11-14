$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Build-FafRe.ps1') -Library
$Workspace = Join-Path ([IO.Path]::GetTempPath()) ('microchip-download-test-' + [guid]::NewGuid().ToString('N'))
$script:requests = 0
$script:alwaysBad = $false
function Invoke-WebRequest {
    param($Uri, $OutFile, [switch]$UseBasicParsing, $TimeoutSec, $Headers)
    $script:requests++
    # A download gateway may return an HTML page with HTTP 200; reject and retry it.
    $text = if ($script:alwaysBad -or $script:requests -eq 1) { 'bad gateway page' } else { 'valid payload' }
    [IO.File]::WriteAllText($OutFile, $text, (New-Object Text.UTF8Encoding($false)))
}
try {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $digest = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes('valid payload'))).Replace('-', '') }
    finally { $sha.Dispose() }
    $path = Get-Download 'https://example.invalid/archive.zip' 'archive.zip' $digest ''
    if ($script:requests -ne 2 -or [IO.File]::ReadAllText($path) -ne 'valid payload') { throw 'Download retry or verification failed.' }
    $cached = Get-Download 'https://example.invalid/archive.zip' 'archive.zip' $digest ''
    if ($cached -ne $path -or $script:requests -ne 2) { throw 'Verified download cache was not reused.' }
    [IO.File]::WriteAllText($path, 'corrupt cache')
    $script:alwaysBad = $true
    $before = $script:requests
    $rejected = $false
    try { Get-Download 'https://example.invalid/archive.zip' 'archive.zip' $digest '' | Out-Null }
    catch { $rejected = $true }
    if (-not $rejected -or $script:requests -ne $before + 3 -or (Test-Path -LiteralPath $path)) { throw 'Corrupt downloads were accepted or retried without a bound.' }
    $rejected = $false
    try { Get-Download 'http://example.invalid/archive.zip' 'archive.zip' $digest '' | Out-Null }
    catch { $rejected = $true }
    if (-not $rejected) { throw 'Insecure URL accepted.' }
    Write-Host 'Worker download tests passed.'
} finally {
    $resolved = [IO.Path]::GetFullPath($Workspace)
    $parent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($resolved.StartsWith($parent, [StringComparison]::OrdinalIgnoreCase) -and (Split-Path $resolved -Leaf) -like 'microchip-download-test-*') {
        if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
    }
}
