# Microchip classic-client test lab

These are real game clients driven by the repository's `mpemu` local lobby
harness. In a mixed test, player 1 hosts on classic FAF, the last seat runs
our installed x64 engine, and **every other seat uses the installed classic
`FAForever/bin/ForgedAlliance.exe`**. No fake game executable stands in for
those classic clients.

## Start a test

Double-click **Compare 2 players.cmd** for the smaller test, or
**Compare 12 players.cmd** for eleven classic peers and one x64 client.
Each launcher first runs an all-classic control, then the mixed test, for
120 seconds after launch in each case. Loading adds extra time. Clients
launch automatically; no public FAF lobby, account login or extra players
are involved. Keep the game windows visible. Ctrl+C stops the test.
Joins are staggered so the classic lobby forms before the x64 client arrives,
matching a player joining an existing classic lobby. A simultaneous 12-client
join burst stalled on missing classic-to-classic links during validation;
such startup failures are reported separately from gameplay performance.

Results are written under `tools/runs/microchip-<time>-<id>/`:

- `performance.csv`: observed simulation ticks per second per client, excluding
  the first 20 seconds of recorded samples. Normal game speed targets ten.
- `runs.json`, each run's `result.json`, and `journal.jsonl`: launch, crash,
  desync and connection results.
- `game-<uid>.log`: the passive recorder, existing game warnings and diagnostics.
- Each run's replays and private preferences, for reproducing failures.

The launcher refuses to start while another game/test is running. It copies
preferences to private `mpemu-p<uid>.prefs` files and enables only a passive
UI test logger there. It does not edit your normal `Game.prefs`, FAF launch
settings or installed executables. The logger is placed in your Mods folder
but is enabled only by the private test profiles. Temporary game clients are
closed by mpemu when the run finishes.

## Other sizes and longer runs

From PowerShell, for example:

```powershell
.\tools\microchip-tests\Run-Classic-Test.ps1 -Players 4 -Seconds 180 -Compare
.\tools\microchip-tests\Run-Classic-Test.ps1 -Players 12 -Seconds 300
```

Supported sizes are 2, 4, 6, 8 and 12. Without `-Compare`, just the mixed test
runs; `-ClassicOnly` runs just the control. `-GenerateOnly` creates the scenario
files without starting clients. `-FafRoot` selects another FAF data folder.
The DualGap Adaptive v0014 map must already be installed; the test is idle
apart from normal commander simulation, not a scripted large battle.

For private investigations, `-X64Renderer d3d9` selects the x64 renderer only;
`-X64DrainProbe` bypasses its display-clock wait with `wld_RunWithTheWind=1`.
The latter changes tick consumption and interpolation and is a diagnostic
probe, not a recommended multiplayer setting. Both are off in the normal
launchers. `-JoinDelaySeconds 5` gives each local join more time (default 2).
These options affect private test launches only, not the FAF client settings.
`-X64LegacyAckProbe` disables the extra order-stream acknowledgement hashes for
that test. `-X64SendRate 8192` instead raises its per-connection send budget
from the original 2048 bytes/second while retaining the hashes. Run these
separately to distinguish extra traffic from checksum computation; both are
diagnostic options and leave the normal launchers at their original defaults.

## Interpret the results carefully

All instances share this PC's CPU, GPU and memory. Twelve local processes can
slow each other down even if x64/classic interoperability is correct. Compare
mixed results with the same-count all-classic control. Loading, shader warm-up,
window occlusion and background work can affect a short run. A measured small
difference is not by itself evidence of an engine defect.

This loopback test does not include the production ICE adapter or internet
routing. It checks local peer compatibility, synchronization and observed tick
progress. A strong internet-routing test needs clients on separate computers.
No additional services are installed and no firewall rules are changed.

## Investigation on 8 November 2026

Working x64 base e4cc5d8b, with passive diagnostics, against the installed
classic engine. Twelve local clients on idle DualGap; figures are mean
per-client ticks/second after warm-up, not graphical FPS.

| Run | Ticks/sec |
| --- | ---: |
| Original all-classic control (60 s) | 9.82 |
| Original mixed, default D3D12 (60 s) | 7.07 |
| Mixed, x64 D3D9 (90 s) | 7.44 |
| Mixed, x64 D3D9, display-clock wait bypassed (90 s) | 7.42 |
| Fresh all-classic control (90 s) | 9.18 |
| Mixed, x64 D3D9, extra ACK hashes disabled (90 s) | 9.18 |
| Mixed, normal D3D12 and hashes, send limit 8192 (90 s) | 9.75 |

The upstream order-stream check (aa7aee84) appends a 16-byte digest to every
advance acknowledgement in `CClientBase::Process`. Its wire message grows
from 8 to 24 bytes, broadcast to all peers for each sender's advance. Twelve
senders at ten advances/second produce about 2880 bytes/second per connection
before compression and other traffic. `net_MaxSendRate` remains 2048, and
`CNetUDPConnection::GetBacklogTimeout` throttles each connection against that
budget. The digest data adds traffic that is difficult to compress. Disabling
the extra hashes restored the fresh control's speed; changing renderer or
bypassing the display-clock wait did not.

Raising only `net_MaxSendRate` to 8192 with the default D3D12 renderer,
normal display pacing and hashes retained restored 9.75 ticks/second (range
9.74-9.77 across all twelve clients), with no reported crash or desync. This
strongly identifies the unchanged send budget combined with larger ACKs as
the cause of the reproduced slowdown. The tested configuration workaround is
`net_MaxSendRate=8192` on the x64 client; a durable engine fix should account
for hash traffic and player count. Normal FAF launch settings were not changed
during this investigation.

Raw logs, scenarios, results and CSVs are under `tools/runs/microchip-investigation-*`
and `tools/runs/microchip-twelve-staggered`. Some attempts stalled on missing
classic-to-classic lobby peers; those did not enter gameplay and are excluded.
Short same-PC runs have resource and order effects; these observations diagnose
the local reproduction, not every possible slowdown in a public game.

## Building the harness

The ready local setup has `tools/bin/mpemu.exe`, `mpemu-server.exe` and
`fakegame.exe`. Rebuild with Go 1.25.5 or later using `tools/build.ps1`.
`fakegame` is used only for harness selftests, not in the real-engine scenarios.
Scenario-generation checks: `Test-ClassicProfiles.ps1`.
