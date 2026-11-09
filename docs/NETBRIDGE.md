# faf-netbridge

`faf-netbridge` replaces FAF's Java ICE adapter (`faf-ice-adapter.jar`) for the FAF client without changing the client (milestone "Network improvements", issues #229–#231). It does the adapter's whole job as [LAUNCHER_ADAPTER_CONTRACT.md](LAUNCHER_ADAPTER_CONTRACT.md) describes it:

- a JSON-RPC server on `--rpc-port` for the client: the 10 methods, the 5 callbacks;
- a GPGNet server on `--gpgnet-port` for the game: `CreateLobby` when the game reports `Idle`, then `HostGame`, `JoinGame`, `ConnectToPeer`, `DisconnectFromPeer`; every message from the game goes to the client;
- one peer link per player (`src/netlink`, on libjuice) and one UDP port per peer on the game's address (`--game-address`, default 127.0.0.1), which the game is told as `<game address>:<port>`.

On the wire a link is a Java adapter link: ICE with the offerer controlling, one `CandidatesMessage` per side through `iceMsg` / `onIceMsg`, `'d'` + game datagram, and the offerer's `'e'` echo every second. Players on the Java adapter and players on the bridge can share a game. It works with the retail game as well as ours, since the game only sees GPGNet and loopback UDP.

## Command line

The launcher's arguments, plus a few of ours:

| Option | Meaning |
|---|---|
| `--id`, `--game-id`, `--login`, `--rpc-port`, `--gpgnet-port` | as the launcher passes them |
| `--force-relay` | relay candidates only, as the Java adapter |
| `--lobby-port <port>` | the game's UDP port; default a free port from 20000 up, as the Java adapter |
| `--access-token`, `--icebreaker-base-url`, others | accepted and ignored |
| `--duplicate-ms <n>` | send every game datagram a second time, `n` ms after the first (0: right after it); off by default (#235). The game drops a repeated DATA packet by its sequence number, so the copy only counts when the first is lost |
| `--webrtc` | offer WebRTC data channels to our own peers (#239, below); also `FAF_NETBRIDGE_WEBRTC=1` |
| `--redundancy <n>` | with our own peers, carry game datagrams on the redundant lane, each repeated up to `n` times until acked (#240, below); 0 (default) is off. Also `FAF_NETBRIDGE_REDUNDANCY=<n>`, and passed to a game that runs its own links (`redundancy` in `NetlinkConfig`) |
| `--no-encrypt` | don't offer to encrypt the redundant lane (#289, below); it is offered by default. Also `FAF_NETBRIDGE_ENCRYPT=0`, and passed to a game that runs its own links (`encrypt` in `NetlinkConfig`) |
| `--test-drop-percent <n>` | tests only: drop n % of the game's datagrams before sending, on either path; on the redundant lane, of the lane's datagrams |
| `--stats-interval <s>` | seconds between statistics lines, default 10; 0 logs them only when a link closes (#241) |
| `--bind-address <ip>` | local address for ICE host candidates (default all interfaces) |
| `--game-address <ip>` | where the game's lobby port is reached, and the address the per-peer ports are bound to and the game is told (default 127.0.0.1) |
| `--log-file <path>` | log file; default `$LOG_DIR/faf-netbridge.log` when the launcher sets `LOG_DIR`. The log also goes to stderr |

`--bind-address` and `--game-address` are for test machines that drop UDP to sockets bound to 0.0.0.0, even over loopback (the game binds its lobby port that way). The environment variables `FAF_NETBRIDGE_BIND_ADDRESS` and `FAF_NETBRIDGE_GAME_ADDRESS` set them too, for runs through the launch shim, which passes only the launcher's arguments.

## Links in the game

Our game with `net_InEngineLinks 1` (startup flag `/inenginelinks`, issue #233) announces itself with `NetlinkHello` after `GameState Idle`. For that game the bridge opens no loopback ports and relays no datagrams: it passes `setIceServers`, `iceMsg` and each new peer to the game over GPGNet, and the game's signalling and link states back to the client ([LAUNCHER_ADAPTER_CONTRACT.md](LAUNCHER_ADAPTER_CONTRACT.md) §8). The game is told `240.x.y.z:p` for each peer and reaches it through its own link. The log says `the game runs the peer links itself`, and per peer `link in the game`. The retail game, and ours with the default 0, keep the relayed path. The bridge's statistics lines cover relayed peers only; the game logs its links with `NETLINK:` lines.

## WebRTC between our peers (layer 2)

With `--webrtc` (or `webrtc` in the game's `NetlinkConfig`) a link marks its ICE ufrag `fnl+w+`. When both sides are ours (#234) and both carry the mark, the offerer opens a WebRTC peer connection beside the ICE link: libdatachannel 0.24.6 (`src/netlink/WebRtc.cpp`), one data channel `game`, unordered with no retransmissions, so the game's own resends stay the only ones. The offer, the answer and trickled candidates go through `iceMsg` / `onIceMsg` like the CandidatesMessage, as JSON text with a `webrtc` member. Only our peers ever see one, and they tell it apart from a CandidatesMessage by that member. Once the channel opens, game datagrams go over it; the ICE link stays up underneath with its echo, and the datagrams go back to it if the channel closes or fails (`WebRTC gave up` in the log). A peer without the mark, the Java adapter included, never sees any of this.

### Redundant lane (layer 3, #240)

With `--redundancy <n>` (or `redundancy` in `NetlinkConfig`, or `net_NativeNetRedundancy` in native mode) a link also marks its ufrag `c+`, after `fnl+` and the optional `w+`. When both sides are ours (#234) and both carry it, game datagrams move into a net channel (`src/remote/net`, [NET_CHANNEL.md](NET_CHANNEL.md)). Each channel datagram carries the new game datagram, plus up to `n` earlier ones the peer has not acknowledged yet. One lost datagram is then covered by the next one, about 30 ms later at the game's rate, instead of by the game's resend timer (100 ms or more). The game's own protocol still runs end to end on top: it drops a repeated packet by its sequence number, so lobby, sim and replays see nothing different.

When the game is quiet, the link's 50 ms timer sends the remaining repeats. On ICE the channel's datagrams go behind a `c` byte; on the WebRTC data channel they go bare (their first byte, `0xFC`, starts no game packet). A new connection starts a new lane on both sides. A peer without the mark, the Java adapter included, never sees any of this.

The log shows `starting WebRTC as offerer`, then `webrtc: data channel open, game datagrams move onto it`.

### Lane encryption (#289)

With the lane on, a link also offers to encrypt it, unless `--no-encrypt` (or `FAF_NETBRIDGE_ENCRYPT=0`, or `net_NativeNetEncrypt 0` in native mode) turns that off. Each connection attempt makes a new X25519 key pair, and its public key ends the ufrag: `fnl+` [`w+`] `c+k+` and 64 lowercase hex digits, in place of the random token (`src/netlink/LinkKeys.h`). The ufrag already travels in the CandidatesMessage, so nothing new is sent and nothing secret is: `iceMsg` carries public keys only. When both ufrags carry a key, each end makes the same two keys, one per direction, with BLAKE2b over the X25519 result and both public keys, and the lane seals every datagram with XChaCha20-Poly1305 from the first one ([NET_CHANNEL.md](NET_CHANNEL.md), Encryption). A reconnect is a new attempt, so it gets new keys and a new lane. A peer whose ufrag has no key (an older build, or a key it can't read) gets the lane as before, unencrypted, and so does a peer with encryption turned off. Without the lane, game datagrams stay plain `'d'` frames.

The log line that moves a link onto the lane ends in `, encrypted` or `, not encrypted`. This keeps game data from anyone on the network path. It doesn't protect against whoever relays `iceMsg`, the lobby server, which could replace or remove the keys.

### faf-pioneer

FAF's WebRTC adapter ([FAForever/faf-pioneer](https://github.com/FAForever/faf-pioneer), Pion) is not a peer for this mode, by decision:

- it signals through faf-icebreaker, a separate server API with its own sessions (its README; the launcher passes `--icebreaker-base-url`), not through `iceMsg`;
- its data channel `gameData` is created with Pion's defaults (`webrtc/peer.go`, "default is ordered"): ordered and reliable. SCTP then retransmits under the game's own resends and holds later datagrams behind a lost one, the second resend layer this mode avoids.

Talking to pioneer would need an icebreaker client in the bridge and a channel with pioneer's settings. Pioneer runs only on the FAF client's `pioneer` branch, so no released client mixes the two.

## Statistics

Every `--stats-interval` seconds and when a link closes, one line per peer:

```
stats periodic, peer Bravo(2) connected: rtt 0.4 ms; to peer 1520 datagrams, 3 game resends, 0 dropped while not connected, 0 copies; from peer 1498 datagrams, 2 lost (0.13%), 0 repeats, 1 late
```

The counts come from the game protocol's header: every packet a connection sends takes the next serial number, resends included, and a resent DATA packet keeps its sequence number. "Lost" are serial numbers that never arrived, "repeats" serial numbers that arrived twice, "game resends" DATA packets the game sent again. The RTT is the offerer's echo; the answerer shows -1.

## The launch shim

The client starts `java -cp <nativeDir>/faf-ice-adapter.jar;<javafx jars> com.faforever.iceadapter.IceAdapter ...` and nothing else. `tools/iceshim` builds a jar with that class (`.\tools\iceshim\build.ps1`, output `tools/iceshim/out/faf-ice-adapter.jar`). The shim starts `faf-netbridge.exe` from its own folder with the same arguments and exits with its exit code. When the bridge is missing, cannot start, or exits with an error within 3 seconds, the shim runs FAF's adapter instead from `faf-ice-adapter.orig.jar` in the same folder.

Installing it is manual and changes the FAF client's folder, so keep a copy of the original:

1. In `C:\Program Files\FAF Client\natives`, rename `faf-ice-adapter.jar` to `faf-ice-adapter.orig.jar`.
2. Copy the shim's `faf-ice-adapter.jar` and `faf-netbridge.exe` into that folder.
3. To go back, delete those two files and rename `faf-ice-adapter.orig.jar` back.

A client update may replace `faf-ice-adapter.jar` again.

## Tests

| What | Command |
|---|---|
| netlink unit checks, two links in one process, 10,000 datagrams each way | `build\...\tests\faf_netlink_tests.exe [--bind <lan ip>]` |
| the client's contract with fake games, any adapter mix | `go run ./cmd/fafclient -players 2 -native-dir <jar folder> -exe <faf-netbridge.exe>,jar -exe-args "--bind-address <lan ip>" -game-bind 127.0.0.1` (from `tools/`) |
| real games through the contract | `mpemu run scenarios/2p-contract-bridge.yaml` (see the scenario for its environment variables) |

## Compatibility matrix (#242)

`tools/netmatrix/netmatrix.py` plays every pair of player kinds through mpemu and writes `results.md`: verdict, the beat both games reached (a cell needs 3000), the longest wait the games reported, and disconnects (the game's `LOBBY: lost connection` / `host disconnected` / `we've been ejected` lines).

| Kind | Player |
|---|---|
| `native` | our build, `/nativenet` (no adapter) |
| `inengine` | our build behind `faf-netbridge`, `/inenginelinks` |
| `bridge` | our build behind `faf-netbridge`, relayed |
| `retail` | the retail game behind `faf-netbridge` |
| `jar` | the retail game behind FAF's `faf-ice-adapter.jar` (`--jar-dir`) |

The jar always sends the game's datagrams to 127.0.0.1, which a host that drops loopback UDP to sockets bound to every interface doesn't deliver. With `--bind`, mpemu stands between the game and the jar (`tools/seat/jarbridge.go`): it renames the jar's addresses in GPGNet and passes the datagrams on over that address, and nothing changes on the jar's links to its peers. A `jar` player's impairment is applied there, on the game's datagrams only, so the jar's own ICE checks and echoes aren't impaired. Use adapter 3.3.14 with mpemu's TURN server: 3.3.15 doesn't pair relayed candidates with private addresses. Without `-turn-ip` set to a reachable address the jars take over 12 s to gather candidates and never connect.

| Profile | Link |
|---|---|
| `direct` | host candidates, no impairment |
| `relay` | relayed candidates only, 25 ms each way |
| `worst` | relayed only, 150 ms each way + up to 50 ms jitter, 5 % loss, one 2 s partition |

The profiles are shaped where each link sends: the scenarios set `shaping: links`, mpemu writes the current impairment to a file, and every netlink link (in our game or in the bridge) reads it through `FAF_NETLINK_TEST_SHAPING` and delays or drops what it sends (`src/netlink/Link.cpp`, `TestShaping`). That holds on whichever path ICE picks. Shaping in mpemu's TURN server (`tools/turnsrv/impair.go`, the default `shaping: turn`) missed some games: with both players on one machine, ICE can settle on a host-to-host path that never reaches the server, even with relayed candidates only. FAF's Java adapter is not a kind: it always sends to 127.0.0.1, which hosts that drop loopback UDP to sockets bound to every interface cannot run. `tools/fafclient` covers it with fake games.

Run it before a pull request that changes `src/netlink`, `src/netbridge` or `src/moho/net` (from `tools/`, with mpemu built):

```
python netmatrix/netmatrix.py --mpemu mpemu.exe --out ../tmp/matrix ^
  --ours <our exe> --retail <ForgedAlliance.exe> --bridge <faf-netbridge.exe> ^
  [--bind <LAN address>] [--jar-dir <folder with faf-ice-adapter.jar>] [--kinds native,retail] [--profiles direct,worst] ^
  --mpemu-args -advertise <LAN address> -turn-ip <LAN address>
```

All 45 cells take about seven hours, one after another.
