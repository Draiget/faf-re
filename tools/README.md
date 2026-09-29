# tools

One Go module (`faf-main/tools`) for development tools. Shared packages sit at
the top level; each program is `cmd/<app>`.

| App | What it is |
|---|---|
| `cmd/mpemu` | Runs multiplayer sessions (on one machine, or across several through a hub) against an emulated FAF client + lobby server, and checks what happened. `mpemu agent` serves one test PC's players. |
| `cmd/mpemu-server` | The hub: icebreaker signalling API, STUN/TURN, the control channel between director and agents, and a latching game relay. Runs on a LAN machine or a remote host known by DNS name. |
| `cmd/fakegame` | Stand-in for the game process: speaks GPGNet, pings every peer over UDP, reports what it measured (`/loadtime` delays `Idle` as the game's loading does) |

| Package | Role |
|---|---|
| `gpgnet` | GPGNet wire codec (int / string / binary data args) and the launcher-side endpoint a game connects to |
| `launcher` | The director (lobby-server half): `HostGame`, full-mesh `JoinGame`/`ConnectToPeer`, `DisconnectFromPeer` on leave, per-mode addressing; local seats directly, remote seats through the hub |
| `seat` | One player's game where it runs (client half): GPGNet endpoint, `CreateLobby` on `Idle`, lobby port, adapter and game processes, private prefs |
| `hub` | Envelopes, hub server (mailboxes, agent presence, per-run relays, ICE/TURN record forwarding) and client |
| `agent` | Runs seats for a remote director with this machine's paths, streams their records back |
| `icebreaker` | Stand-in for faf-icebreaker (the signalling service faf-pioneer talks to): token, session, SSE events, log upload |
| `bus` | In-process queue replacing RabbitMQ: per-user mailboxes that hold messages until the peer subscribes |
| `turnsrv` | Embedded Pion TURN/STUN replacing eturnal, same shared-secret REST credentials |
| `relay` | UDP pair proxy for runs without WebRTC: latency, jitter, loss, duplication, partitions |
| `journal` | The run's database: every GPGNet message, signalling event, TURN allocation, relay counter and process exit, queryable and mirrored to `journal.jsonl` |
| `scenario` | YAML scenarios, step runner, assertions, interactive console |
| `procs` | Child processes in a kill-on-close job object: nothing survives mpemu |
| `fakegame` | Library behind `cmd/fakegame` |

## Build

```powershell
.\build.ps1          # bin\mpemu.exe, bin\mpemu-server.exe, bin\fakegame.exe,
                     # and bin\faf-adapter.exe from ..\..\faf-pioneer if present
.\build.ps1 -Debug   # no optimisation, for Delve / VS Code / GoLand
go test ./...
```

## Several machines

```
 director (mpemu run/lobby)        agent (mpemu agent)         agent (mpemu agent)
   local seats                       seats on PC 2                seats on PC 3
        \                                 |                            /
         `------------ outbound HTTPS to the hub (mpemu-server) ------'
                      icebreaker + TURN + control + game relay
```

Everyone connects *to* the hub, so NAT on any side is fine. Players name the
agent that runs them (`agent: pc2`; empty = the director's machine). The
modes then mean:

- `direct`: games talk to each other's LAN addresses (agents advertise theirs).
- `relay`: every pair goes through the hub's relay, which learns each game's
  public address from its first packet. Impairment and partitions work as
  locally.
- `ice`: the adapters use the hub's icebreaker and TURN.

Hub URL and secret come from the environment, never from committed files:

```powershell
$env:MPEMU_HUB = 'https://faftest.zontwelg.net:8443'     # internet hub (altair); LAN: https://<lan-hub-host>:8443
$env:MPEMU_SECRET_FILE = "$env:APPDATA\mpemu\secret"     # same secret everywhere
.\bin\mpemu.exe selftest -remote                         # check the hub from this PC (fakegame, no windows)
.\bin\mpemu.exe agent -name pc2                          # on every PC with players
.\bin\mpemu.exe lobby -n 2 -agents ",pc2" -mode relay    # director; player 1 here, player 2 on pc2
```

Host names in `JoinGame` and `ConnectToPeer` are resolved by each seat on its
own machine, so a hub name that resolves differently in the LAN and on the
internet still works.

The API is TLS under a key derived from the secret, so a hub known only by an
internal DNS name needs no certificate. `deploy/README.md` covers the
deployed hubs and how to install another.

## Network modes

| Mode | Game UDP path | Needs |
|---|---|---|
| `direct` | game ↔ game on 127.0.0.1 | nothing |
| `relay` | game ↔ mpemu relay ↔ game; links can be impaired or cut | nothing |
| `ice` | game ↔ faf-pioneer adapter ↔ WebRTC data channel ↔ adapter ↔ game, signalled via mpemu's icebreaker, optionally forced through mpemu's TURN | `bin\faf-adapter.exe` |

No Docker, database, RabbitMQ or eturnal is involved: all of it runs inside
mpemu.

## Use

```powershell
# Check the whole stack without the game (no windows): all modes, plus the
# multi-machine path with a local hub and two agent processes.
.\bin\mpemu.exe selftest

# N instances, host + join, then an interactive console (help lists the commands).
.\bin\mpemu.exe lobby -n 2 -mode relay
.\bin\mpemu.exe lobby -n 2 -mode ice -force-relay

# A scripted scenario; exit code 0 = PASS. Output lands in runs\<time>-<name>\.
.\bin\mpemu.exe run scenarios\2p-direct-smoke.yaml
.\bin\mpemu.exe run scenarios\2p-recovered-vs-original.yaml
```

Shipped scenarios (`scenarios/`):

| File | Checks |
|---|---|
| `2p-direct-smoke.yaml` | Baseline: two shipped-game instances launch and play 2 minutes, no desync, no crash |
| `2p-ice-turn.yaml` | The production path: faf-pioneer adapters, TURN relay forced (`relayOnly`, `minTurnAllocations`) |
| `3p-relay-lag-and-drop.yaml` | 150 ms ± 30 ms and 3 % loss on one link, a 20 s partition, then a crash; survivors stay in sync |
| `2p-recovered-vs-original.yaml` | Recovered `main.exe` against `ForgedAlliance.exe` in one match; divergence shows up as a `Desync` report |
| `2p-debug-main.yaml` | Player 2 is started by you under the debugger; mpemu prints its command line and waits |

### What every game instance gets

```
/init <FAF bin>\init.lua /nobugreport /gpgnet 127.0.0.1:<port> /log <run>\game-<uid>.log
/windowed 1600 1000 /players N /team T /startspot S /nosound /prefs mpemu-p<uid>.prefs /position x y
```

- **Always windowed.** `/windowed W H` is always passed (the engine's own flag,
  0x008D02D0), and any `/fullscreen` in a scenario is rejected when the scenario is loaded. Size: `game.window`.
- **Private preferences.** The engine resolves `/prefs` as a *file name inside*
  `%LOCALAPPDATA%\Gas Powered Games\Supreme Commander Forged Alliance`. A path
  silently gives empty preferences. Each instance gets a copy of `Game.prefs`
  there as `mpemu-p<uid>.prefs`, moved into the run directory afterwards. Your
  `Game.prefs` is never written. `prefs: shared` turns this off.
- **Autolobby** (`lobby: auto`) launches by itself once every player is
  connected to every other. It indexes players by start spot, so start spots
  must be 1..N and unique (mpemu assigns them).

## Scenario format

```yaml
name: example
timeout: 10m
mode: relay                # direct | relay | ice
lobby: auto                # auto | normal
map: SCMP_009              # map folder name for HostGame
game:
  exe: '%ProgramData%\FAForever\bin\ForgedAlliance.exe'
  window: { width: 1600, height: 1000 }
  nosound: true
  tile: true
  spawn: true              # false: print the command line and wait (debugger)
ice: { forceRelay: false, noTurn: false, logLevel: 0 }
link: { latency: 0ms }     # default impairment for new relay links
players:
  - { uid: 1, name: Alpha }
  - { uid: 2, name: Bravo, exe: '%ProgramData%\FAForever\bin\main.exe' }
steps:
  - start: all
  - host: 1
  - join: others
  - waitState: { uids: all, state: Launching, timeout: 5m }
  - wait: 60s
  - link: { from: 1, to: 2, latency: 150ms, jitter: 20ms, loss: 0.02 }   # oneWay: true for one direction
  - isolate: 2             # cut all of player 2's links; restore: 2 undoes it
  - kill: 2                # terminate, as a crash would
  - send: { uid: 1, cmd: Chat, args: [hello] }
  - waitMessage: { uid: 1, cmd: GameState, arg: Ended, timeout: 20m }
  - check: { noDesync: true }
  - interactive: true      # console until "continue" / "quit"
expect:
  allLaunched: true
  noDesync: true
  noCrash: true            # no game/adapter exited unless mpemu killed it
  present: [{ uid: 2, cmd: GameState, arg: Launching }]
  absent:  [{ cmd: Bottleneck }]
  minTurnAllocations: 2
  relayOnly: true
  peerStats: { minAnswered: 20, maxAvgRtt: 50ms, maxLoss: 0.02 }   # fakegame only
```

## Debugging

- **The engine:** set `spawn: false` on a player (see `2p-debug-main.yaml`).
  mpemu prints the exact working directory and arguments, and also writes
  `debug-args-<uid>.txt` and `start-game-<uid>.cmd` into the run directory.
  Run the exe from `%ProgramData%\FAForever\bin`; elsewhere it dies at startup.
- **The Go side:** everything except the games and adapters runs in the one
  mpemu process: `dlv debug ./cmd/mpemu -- lobby -n 2`.
- **The adapter:** `mpemu-server` gives you the icebreaker and TURN on fixed
  ports and prints ready-made access tokens. Run `faf-adapter` under a debugger
  against it.
- **After the fact:** `journal.jsonl` holds the whole run, `result.json` the
  verdict. In `ice` mode the icebreaker's `GET /debug/state` shows members,
  pending queue depth and TURN allocations live.

## Known limits

- faf-pioneer restarts a peer whose first WebRTC offer is still unanswered
  when `ConnectToPeer` arrives. `addPeerIfMissing` treats the peer as
  inactive, and `scheduleReconnection` only spares peers in the `connecting`
  state. The other side is never told, so it answers the old offer and the
  two never agree again ("stable->SetRemote(answer)").
  - The real game loads for seconds before `Idle`, and ICE usually
    finishes in that time.
  - Through a distant TURN server, a game that is ready almost at once hits
    the race every time. The remote ICE selftest therefore gives fakegame
    `/loadtime 4s`; drop that to reproduce the bug.
- faf-pioneer's GPGNet reader (`faf/stream_reader.go`) drops the connection on
  a message with more than 10 arguments or a string over 64 KiB. End-of-game
  `JsonStats` exceeds that in larger games, so in `ice` mode the adapter can
  lose its launcher link exactly at game end. mpemu's own codec has no such
  limit.
- Several instances run on one GPU. mpemu keeps them windowed; exclusive
  fullscreen instances fail to create their D3D9 device.
