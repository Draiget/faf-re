<#
.SYNOPSIS
  Installs (or updates) the mpemu hub on this Windows machine as a LAN hub
  that starts at boot.

.DESCRIPTION
  Run it on the hub machine itself, in an elevated PowerShell, from a copy of
  tools\ (it needs bin\mpemu-server.exe next to deploy\). It:

    - copies mpemu-server.exe to %ProgramData%\mpemu;
    - stores the shared secret there, readable by SYSTEM and Administrators
      only (from -SecretFile: a copy of the secret every test PC uses);
    - checks that every port the hub needs is free, and stops if another
      program holds one;
    - allows those ports inbound in Windows Firewall, for mpemu-server.exe
      only (rule group "mpemu");
    - registers the scheduled task "mpemu hub" (at startup, as SYSTEM,
      restarted on failure, below-normal priority) and starts it.

  The API is TLS under a key derived from the secret, so no certificate is
  needed. Uninstall with -Uninstall.

.EXAMPLE
  # on the hub machine, elevated, with the secret file copied next to tools\:
  .\install-windows.ps1 -PublicHost <lan-hub-host> -SecretFile ..\secret
  # then on each test PC:
  #   $env:MPEMU_HUB = 'https://<lan-hub-host>:8443'
#>
param(
    [string]$PublicHost,
    [string]$SecretFile,
    [int]$ApiPort = 8443,
    [int]$TurnPort = 3479,
    [string]$TurnRelayPorts = '40000-40015',
    [string]$RelayPorts = '40100-40131',
    [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$task = 'mpemu hub'
$dir = Join-Path $env:ProgramData 'mpemu'
$exe = Join-Path $dir 'mpemu-server.exe'

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'run this from an elevated PowerShell' }

function Remove-Hub {
    if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $task -Confirm:$false
    }
    Get-Process mpemu-server -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe } | Stop-Process -Force
    Get-NetFirewallRule -Group 'mpemu' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}

if ($Uninstall) {
    Remove-Hub
    Write-Host "removed the task and firewall rules; $dir (logs, secret) is left for you to delete"
    return
}
if (-not $PublicHost) { throw '-PublicHost is required: the name test PCs reach this machine by' }
if (-not $SecretFile -or -not (Test-Path $SecretFile)) { throw '-SecretFile must name a copy of the shared secret file' }
$source = Join-Path (Split-Path $PSScriptRoot -Parent) 'bin\mpemu-server.exe'
if (-not (Test-Path $source)) { throw "$source not found (run build.ps1, or copy bin\ next to deploy\)" }

function Expand-Range([string]$r) {
    $lo, $hi = $r -split '-'
    [int]$lo..[int]$hi
}

# 1. Ports: stop if a program other than the hub holds one.
Remove-Hub   # an older hub instance would hold them
$clash = @()
Get-NetTCPConnection -State Listen -LocalPort $ApiPort -ErrorAction SilentlyContinue |
    ForEach-Object { $clash += "tcp/$ApiPort (pid $($_.OwningProcess))" }
foreach ($p in @($TurnPort) + (Expand-Range $TurnRelayPorts) + (Expand-Range $RelayPorts)) {
    Get-NetUDPEndpoint -LocalPort $p -ErrorAction SilentlyContinue |
        ForEach-Object { $clash += "udp/$p (pid $($_.OwningProcess))" }
}
if ($clash) { throw "ports already in use: $($clash -join ', ')" }

# 2. Files. The secret is for SYSTEM (the task) and Administrators only.
New-Item -ItemType Directory -Force $dir, (Join-Path $dir 'logs') | Out-Null
Copy-Item $source $exe -Force
$secret = Join-Path $dir 'secret'
Copy-Item $SecretFile $secret -Force
& icacls $secret /inheritance:r /grant:r 'SYSTEM:(R)' 'Administrators:(F)' | Out-Null

# 3. Firewall: inbound for the hub's executable only.
$rules = @(
    @{ Name = "TCP $ApiPort (API)"; Protocol = 'TCP'; Port = "$ApiPort" },
    @{ Name = "UDP $TurnPort (TURN/STUN)"; Protocol = 'UDP'; Port = "$TurnPort" },
    @{ Name = "UDP $TurnRelayPorts (TURN relays)"; Protocol = 'UDP'; Port = $TurnRelayPorts },
    @{ Name = "UDP $RelayPorts (game relay)"; Protocol = 'UDP'; Port = $RelayPorts }
)
foreach ($r in $rules) {
    New-NetFirewallRule -DisplayName "mpemu hub $($r.Name)" -Group 'mpemu' -Direction Inbound -Action Allow `
        -Program $exe -Protocol $r.Protocol -LocalPort $r.Port -Profile Any | Out-Null
}

# 4. The task.
$argv = @(
    '-http', "0.0.0.0:$ApiPort", '-public-host', $PublicHost,
    '-turn-port', $TurnPort, '-turn-relay-ports', $TurnRelayPorts, '-relay-ports', $RelayPorts,
    '-secret-file', "`"$secret`"", '-logs', "`"$(Join-Path $dir 'logs')`""
) -join ' '
$action = New-ScheduledTaskAction -Execute $exe -Argument $argv -WorkingDirectory $dir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -Priority 7 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description 'mpemu hub: FAF multiplayer test server (icebreaker, TURN, relay, control)' | Out-Null
Start-ScheduledTask -TaskName $task

# 5. Check it listens. (Windows PowerShell cannot speak TLS to it: the
# certificate key is Ed25519, which SChannel does not support; mpemu can.)
$up = $false
foreach ($i in 1..20) {
    Start-Sleep -Milliseconds 500
    if (Get-NetTCPConnection -State Listen -LocalPort $ApiPort -ErrorAction SilentlyContinue) { $up = $true; break }
}
if (-not $up) { throw "the hub did not start listening on tcp/$ApiPort; see $dir\logs and the task's history" }
Write-Host @"
mpemu hub installed and listening on tcp/$ApiPort (task '$task', starts at boot).
Test PCs: MPEMU_HUB=https://${PublicHost}:$ApiPort and MPEMU_SECRET_FILE=<their copy of the same secret>.
Check from a test PC:  mpemu selftest -remote
"@
