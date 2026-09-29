# Deploying the mpemu hub

The hub (`cmd/mpemu-server`) is what every machine of a multi-machine run
talks to. It serves:

- the icebreaker signalling API;
- STUN/TURN;
- the control channel between the director and the agents;
- the latching game relay.

Machines only ever connect *out* to it, so it has to be reachable from all of
them. Nothing in this repository names a host or an address: machines use a
DNS name, and the address lives only in DNS, in your ssh config and on the
host itself.

## TLS without certificates

With a secret set, the hub serves its API over TLS under a key derived from
the secret (`hub.ServerTLS`). Every director and agent holds the secret, so
they check the hub by that key (`hub.ClientTLS`) and need no CA, certificate
file or public DNS record: the name can exist only in fw0's internal DNS.
The ICE adapter trusts public CAs only, so each mpemu process gives its
adapters a loopback gateway to the icebreaker API (`hub.Client.Gateway`).

`-tls-cert`/`-tls-key` serve a real certificate instead; clients accept one
that the system trusts for the host name. `-tls off` serves plain HTTP for a
TLS proxy in front.

## What has to reach the hub

| Port | Protocol | Purpose |
|---|---|---|
| 8443 | TCP | API and event streams, TLS |
| 3479 | UDP | STUN/TURN (not 3478: ShadowLink holds that on the VPN servers) |
| 40000-40015 | UDP | TURN relay allocations (a 4-player game needs up to 12) |
| 40100-40131 | UDP | game relay sockets (2 per player pair; 6 players need 30) |

The ranges are small and fixed so that a firewall forwarding single ports
(fw0) needs few rules.

## Internet hub: `faftest.zontwelg.net`

Runs on altair, fw0's reserve ShadowLink server (GE). It was picked because
it had the lowest round trip from fw0 when measured (30 pings each):
62.4 ms against 64.3 ms for deneb (NL). It is also the reserve server, so
the hub stays off the tunnel that carries the LAN's traffic.

- **Install or update:** `.\deploy-remote.ps1 -SshHost ge-gw`. The alias
  lives in `~/.ssh/config`. The script:
  - builds the Linux binary;
  - refuses to install if another service holds any of the ports;
  - installs the systemd unit `mpemu-server` (at most half a core and
    256 MiB, niced, sandboxed);
  - writes `/etc/mpemu/mpemu-server.env` (mode 0600) over ssh stdin;
  - checks `/healthz` over TLS on the host.
- **Name:** an internal zone on fw0, `faftest.zontwelg.net`, holding one
  `A` record for the host. It was added with:

  ```
  zwfwctl dns zone add faftest.zontwelg.net --type native
  zwfwctl dns record add faftest.zontwelg.net @ --type A --value <address> --ttl 60
  ```

  The hub cannot resolve that name itself, so TURN announces the host's
  outbound address.
- **Firewall:** the host accepts all inbound traffic. The provider lets the
  UDP ports through; this was checked with probes captured on the host.
- **Test PCs:**
  - `MPEMU_HUB=https://faftest.zontwelg.net:8443`;
  - `MPEMU_SECRET_FILE` pointing at a copy of `%APPDATA%\mpemu\secret`,
    which is the file the deploy script created.

## LAN hub: `<lan-hub-host>`

A Windows machine; run this on it once, in an elevated PowerShell, from a
copy of `tools\` with `bin\` built and the secret file copied alongside:

```powershell
.\deploy\install-windows.ps1 -PublicHost <lan-hub-host> -SecretFile ..\secret
```

The script:

1. refuses to install if another program holds any of the ports;
2. copies the hub to `%ProgramData%\mpemu`, with the secret readable by
   SYSTEM and Administrators only;
3. allows the ports inbound in Windows Firewall, for that executable only
   (rule group `mpemu`);
4. registers the startup task `mpemu hub` (runs as SYSTEM, restarts on
   failure) and starts it.

Test PCs then use `MPEMU_HUB=https://<lan-hub-host>:8443`.
`-Uninstall` removes the task and the rules.

## Checking a hub

From any test PC with `MPEMU_HUB` and the secret set:

```powershell
.\bin\mpemu.exe selftest -remote
```

This starts two agents on this PC under names unique to it. It then runs:

- the hub's direct scenario;
- the relay scenario, with an impaired link and an isolated player;
- the ICE scenario, forced through the hub's TURN with the real faf-pioneer
  adapters.

All of it uses the stand-in game, so no game windows open. Relayed paths
cross the hub twice, so they are checked for connectivity, impairment and
loss rather than loopback latency.

## Home cluster (not used)

Possible, but it takes the most work:

- UDP into the cluster needs its own MetalLB `LoadBalancer` Service. The
  ingress-nginx `udp:` map is per-port.
- fw0 needs one `nat.dnat` entry per port, because its schema has no port
  ranges.
- 80/443 on fw0 already go to the ingress.
- `docker build -f deploy/Dockerfile .` from `tools/` builds the image.
- The secret would come from Vault through the secrets-store CSI driver.
