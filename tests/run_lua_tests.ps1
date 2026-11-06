# tests/run_lua_tests.ps1
# Runner for Lua unit tests across the repository and mods

$ErrorActionPreference = "Stop"

function Find-LuaExecutable {
    $candidates = @(
        (Get-Command luajit -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue),
        (Get-Command lua -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue),
        "$env:LOCALAPPDATA\Programs\LuaJIT\bin\luajit.exe",
        "$env:ProgramFiles\LuaJIT\bin\luajit.exe",
        "$env:ProgramFiles(x86)\LuaJIT\bin\luajit.exe"
    )

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return $candidate
        }
    }
    return $null
}

$luaExe = Find-LuaExecutable
if (-not $luaExe) {
    Write-Error "Lua executable (lua or luajit) not found in PATH or standard installation directories."
    exit 1
}

Write-Host "Using Lua runner: $luaExe"

$testFiles = Get-ChildItem -Path "$PSScriptRoot\lua" -Filter "test_*.lua"
if ($testFiles.Count -eq 0) {
    Write-Warning "No test files matching test_*.lua found in $PSScriptRoot\lua"
    exit 0
}

$failed = $false
foreach ($test in $testFiles) {
    Write-Host "Running $($test.Name)..."
    & $luaExe $test.FullName
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Test $($test.Name) failed with exit code $LASTEXITCODE"
        $failed = $true
    }
}

if ($failed) {
    exit 1
}

Write-Host "All Lua unit tests passed successfully."
exit 0
