# Mixed classic/faf-re multiplayer slowdown: ACK traffic and send budget

Author: Microchip

Investigation date: 8 November 2026

Project: https://github.com/Draiget/faf-re

Tested upstream engine base: `e4cc5d8b03cc29a9100fa29f08eea57f6aaa0a95`, x64 Release, with local passive diagnostics.

## Finding

In a local 12-player reproduction, one faf-re client plus eleven classic FAF clients ran at approximately 7.1-7.4 simulation ticks/second instead of the normal target of ten. Raising **only the faf-re client's `net_MaxSendRate` from 2048 to 8192 bytes/second per peer**, with order-stream checks enabled, restored 9.75 ticks/second. No crash or desync was reported in that completed run.

This strongly identifies the combination of larger acknowledgement messages and the unchanged send budget as the bottleneck in this reproduction. It is not an inherent consequence of 64-bit execution or a fast CPU forcing slower machines to render faster.

## Relevant code and mechanism

- `src/moho/net/CClientBase.cpp`, `CClientBase::Process`: each `CMDST_Advance` creates an ACK containing a sender index and queued beat, then broadcasts it through `ProcessClients`. With `net_CheckOrderStreams` enabled, it appends an order-stream digest.
- `src/moho/net/CommandStreamCheck.h`: `kAckDigestBytes` is 16. Including the three-byte message header, the ACK grows from **8 to 24 bytes**. The upstream check was introduced in commit `aa7aee84`.
- `src/moho/net/NetConVars.cpp`: checks are enabled by default, but `net_MaxSendRate` remains the retail value of **2048**.
- `src/moho/net/CNetUDPConnection.cpp`, `GetSentTime`, `GetBacklogTimeout`, and the send path: outgoing packet bytes accumulate against a per-connection rate budget; excess backlog delays sending.

At twelve senders and approximately ten advances per sender per second, uncompressed ACK messages alone are approximately `12 * 10 * 24 = 2880 bytes/second` to each remote peer, before other traffic. This is an illustrative estimate, not a packet capture: advances can be batched, transport overhead and compression affect the wire rate, and hash data is difficult to compress. Delayed confirmations hold up the lockstep simulation for everyone.

Classic peers completed the mixed tests; they do not provide the extra order-stream comparison themselves. This report does not claim compatibility with every historical classic build.

## Controlled results

Windows, RTX 3070, roughly 32 GB system RAM. Real game processes through the repository's Go `mpemu` harness, direct loopback connections, classic host, x64 client in seat 12, idle `dualgap_adaptive.v0014`, normal game speed. Separate private preferences enabled passive logging. No fake game executable represented the classic clients.

Figures below average observed per-client simulation tick progress against wall time, excluding the first 20 seconds of recorded samples. Graphical FPS is a separate measure.

| Configuration | Gameplay observation | Mean ticks/sec |
| --- | ---: | ---: |
| Original 12-client all-classic control | 60 s | 9.82 |
| Original 11 classic + 1 faf-re, default D3D12 | 60 s | 7.07 |
| Mixed, faf-re changed to D3D9 | 90 s | 7.44 |
| Mixed, D3D9 and display-clock wait bypassed | 90 s | 7.42 |
| Fresh all-classic control | 90 s | 9.18 |
| Mixed, D3D9, `net_CheckOrderStreams=0` | 90 s | 9.18 |
| Mixed, normal D3D12, checks enabled, `net_MaxSendRate=8192` | 90 s | **9.75** |

The last run ranged from 9.74 to 9.77 ticks/sec across all twelve clients and passed the harness's no-crash/no-desync checks. Earlier two-player controls were approximately 9.76 all-classic and 9.66 mixed. Changing the renderer or bypassing the faf-re display-clock wait did not resolve the 12-player slowdown; removing the extra ACK hashes or increasing the send budget did.

## Workaround and proposed patch

Before creating the multiplayer simulation, execute this on the faf-re client:

```text
net_MaxSendRate 8192
```

Alternatively, add `net_MaxSendRate=8192` to its existing `/con` launch argument. Keep `net_CheckOrderStreams=1` to retain the extra checks. Classic peers do not need their send limits changed for this workaround. The setting raises a ceiling; it does not force continuous 8 KB/sec transmission, and it is a per-peer limit rather than a whole-game total.

The accompanying **`faf-re-ack-send-budget.patch`** changes the rebuilt engine's default to 8192, retains checksum validation, and leaves the existing console override available. It changes no packet format, tick rate, ACK delay, or backlog threshold. This is a small default-budget fix; it is not an adaptive bandwidth algorithm or proof that 8192 is sufficient for every larger or busier game.

From the repository root:

```sh
git apply --check /path/to/faf-re-ack-send-budget.patch
git apply /path/to/faf-re-ack-send-budget.patch
```

Build using the project's normal instructions, then repeat the mixed/classic comparison. To undo an applied patch, use `git apply -R /path/to/faf-re-ack-send-budget.patch`.

The patch was checked and applied successfully to temporary copies of the tested upstream base file and a newer local checkout. The gameplay result above used the equivalent runtime console setting on the existing executable; **a newly compiled executable containing this patch has not been tested**.

Our separate local lobby customization also provides a persistent **Checksums: On/Off** button beside Lag Test. On sets `net_CheckOrderStreams=1` and the 8192 send limit; Off sets `net_CheckOrderStreams=0`. That custom UI is not included in the upstream engine patch. Disabling the extra check is useful diagnostically but is unnecessary for the tested bandwidth fix.

## Reproduction and limits

With the local test helpers from this investigation:

```powershell
.\tools\microchip-tests\Run-Classic-Test.ps1 -Players 12 -Seconds 90 -ClassicOnly -JoinDelaySeconds 5
.\tools\microchip-tests\Run-Classic-Test.ps1 -Players 12 -Seconds 90 -JoinDelaySeconds 5
.\tools\microchip-tests\Run-Classic-Test.ps1 -Players 12 -Seconds 90 -X64SendRate 8192 -JoinDelaySeconds 5
```

For upstream reproduction without those local helpers, use `mpemu` with a classic host, eleven classic clients and one faf-re client, keeping the same map, settings and observation window. Compare the default budget with `/con net_MaxSendRate=8192` on faf-re. Retain checks and normal pacing. Wait for actual tick progress rather than counting a lobby launch as gameplay.

Raw local evidence is retained under `tools/runs/microchip-twelve-staggered` and `tools/runs/microchip-investigation-*`: scenario files, `performance.csv`, per-game logs, journals and `result.json`. These ignored run directories are not included in this report or patch.

All clients shared one PC and GPU; tests were short and not randomized. Fresh classic-control variation demonstrates some environmental noise. This test excludes production ICE, internet routing and a large battle. Several attempts stalled on missing classic-to-classic lobby links before gameplay; those attempts were excluded. The findings support this local bottleneck, not a guarantee that it explains every reported public-game slowdown. Separate-machine tests, traffic/backlog measurements, longer games and a rebuilt-patch regression run would strengthen upstream validation.
