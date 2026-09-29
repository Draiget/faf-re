<#
.SYNOPSIS
  Installs (or updates) the mpemu hub on a Linux host as a systemd service.

.DESCRIPTION
  The host is given as an ssh config alias or user@host on the command line,
  so no address is stored here or in the repository. The shared secret is
  read from a local file outside the repository (created on first use) and
  piped to the host over ssh stdin, never put on a command line.

  The API is served over TLS under a key derived from the secret, so neither
  a certificate nor a public DNS record is needed: the name can live only in
  the LAN's DNS (fw0).

  Before installing, the script checks that every port the hub needs is free
  on the host (or already held by the hub), and stops if anything else holds
  one: the hub is meant to sit next to other services (the VPN servers)
  without disturbing them. It changes neither the host's firewall nor DNS.

  Needs: ssh/scp and go on PATH; root or sudo on the host.

.EXAMPLE
  .\deploy-remote.ps1 -SshHost ge-gw
  # then on each test PC:
  #   $env:MPEMU_HUB = 'https://faftest.zontwelg.net:8443'
  #   $env:MPEMU_SECRET_FILE = "$env:APPDATA\mpemu\secret"
#>
param(
    [Parameter(Mandatory)] [string]$SshHost,
    [string]$PublicHost = 'faftest.zontwelg.net',
    [string]$SecretFile = (Join-Path $env:APPDATA 'mpemu\secret'),
    [string]$Listen = '0.0.0.0:8443',
    [int]$TurnPort = 3479,
    [string]$TurnRelayPorts = '40000-40015',
    [string]$RelayPorts = '40100-40131'
)
$ErrorActionPreference = 'Stop'
$tools = Split-Path $PSScriptRoot -Parent

# ssh/scp report through exit codes. Their stderr (a host's login noise, for
# one) must not become a terminating error when the caller redirects it.
function Invoke-Native([scriptblock]$command) {
    $eap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $command } finally { $ErrorActionPreference = $eap }
}

# Runs a bash script on the host. It travels on stdin, not as an argument:
# Windows PowerShell mangles double quotes in native arguments, and anything
# on stdin stays out of process listings (the env file below carries the
# secret). The pipe is UTF-8 without a BOM, and Windows line endings (and a
# BOM, should one slip through) are stripped on arrival.
function Invoke-HostScript([string]$script) {
    $OutputEncoding = New-Object System.Text.UTF8Encoding $false
    Invoke-Native { ($script -replace "`r", '') | & ssh $SshHost "tr -d '\r' | sed '1s/^\xEF\xBB\xBF//' | bash -s" }
}

# 1. Secret: generate once, keep it private to this Windows user.
if (-not (Test-Path $SecretFile)) {
    New-Item -ItemType Directory -Force (Split-Path $SecretFile) | Out-Null
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    Set-Content -Path $SecretFile -Value (($bytes | ForEach-Object { $_.ToString('x2') }) -join '') -NoNewline -Encoding ascii
    icacls $SecretFile /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null
    Write-Host "created secret file $SecretFile (copy it to every test PC that runs an agent)"
}
$secret = (Get-Content $SecretFile -Raw).Trim()

# 2. Build the Linux binary.
$out = Join-Path $tools 'bin\linux'
New-Item -ItemType Directory -Force $out | Out-Null
Push-Location $tools
try {
    $env:GOOS = 'linux'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'
    & go build -trimpath -ldflags '-s -w' -o (Join-Path $out 'mpemu-server') ./cmd/mpemu-server
    if ($LASTEXITCODE -ne 0) { throw 'go build failed' }
} finally {
    Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue
    Pop-Location
}

# 3. Check the host's ports before touching anything on it.
$httpPort = ($Listen -split ':')[-1]
$vars = "HTTP_PORT=$httpPort; TURN_PORT=$TurnPort; TURN_RANGE=$TurnRelayPorts; RELAY_RANGE=$RelayPorts`n"
$preflight = @'
set -e
SUDO=; [ "$(id -u)" = 0 ] || SUDO=sudo
needed="tcp:$HTTP_PORT udp:$TURN_PORT"
for p in $(seq "${TURN_RANGE%-*}" "${TURN_RANGE#*-}") $(seq "${RELAY_RANGE%-*}" "${RELAY_RANGE#*-}"); do
  needed="$needed udp:$p"
done
in_use=$($SUDO ss -Htulnp)
clash=""
for spec in $needed; do
  proto=${spec%%:*}; port=${spec#*:}
  line=$(printf '%s\n' "$in_use" | awk -v p="$proto" -v port="$port" '$1==p && $5 ~ (":" port "$") {print; exit}')
  [ -z "$line" ] && continue
  case "$line" in *'"mpemu-server"'*) ;; *) clash="$clash $proto/$port";; esac
done
if [ -n "$clash" ]; then echo "ports already held by another service on this host:$clash" >&2; exit 3; fi
echo "ports free: tcp/$HTTP_PORT udp/$TURN_PORT udp/$TURN_RANGE udp/$RELAY_RANGE"
'@
Invoke-HostScript ($vars + $preflight)
if ($LASTEXITCODE -ne 0) { throw "port check failed on $SshHost; nothing was installed" }

# 4. Copy and install.
Invoke-Native { & scp -q (Join-Path $out 'mpemu-server') (Join-Path $PSScriptRoot 'mpemu-server.service') "${SshHost}:/tmp/" }
if ($LASTEXITCODE -ne 0) { throw 'scp failed' }

$envBody = @"
MPEMU_SECRET=$secret
MPEMU_PUBLIC_HOST=$PublicHost
MPEMU_HTTP=$Listen
MPEMU_TURN_PORT=$TurnPort
MPEMU_TURN_RELAY_PORTS=$TurnRelayPorts
MPEMU_RELAY_PORTS=$RelayPorts
"@
$install = @'
set -e
SUDO=; [ "$(id -u)" = 0 ] || SUDO=sudo
$SUDO install -d -m 0755 /opt/mpemu /etc/mpemu
$SUDO install -m 0755 /tmp/mpemu-server /opt/mpemu/mpemu-server
$SUDO install -m 0644 /tmp/mpemu-server.service /etc/systemd/system/mpemu-server.service
$SUDO sh -c 'umask 077; cat > /etc/mpemu/mpemu-server.env' <<'MPEMU_ENV'
@ENV@
MPEMU_ENV
rm -f /tmp/mpemu-server /tmp/mpemu-server.service
$SUDO systemctl daemon-reload
$SUDO systemctl enable mpemu-server >/dev/null 2>&1
$SUDO systemctl restart mpemu-server
sleep 2
$SUDO systemctl is-active mpemu-server
$SUDO journalctl -u mpemu-server -n 12 --no-pager -o cat
code=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$HTTP_PORT/healthz" || true)
echo "healthz over TLS on the host: ${code:-no answer}"
'@
Invoke-HostScript ($vars + $install.Replace('@ENV@', $envBody))
if ($LASTEXITCODE -ne 0) { throw 'remote install failed' }

Write-Host @"

Installed. Not automated (outside this host):
  - DNS: $PublicHost -> this host. An internal zone on fw0 is enough; no
    public record or certificate is needed.
  - Firewall (host and provider): TCP $httpPort; UDP $TurnPort; UDP $TurnRelayPorts; UDP $RelayPorts.
  - Test PCs: MPEMU_HUB=https://${PublicHost}:$httpPort and MPEMU_SECRET_FILE=<copy of $SecretFile>.
"@
