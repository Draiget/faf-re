# faf-netbridge

`faf-netbridge` replaces FAF's Java ICE adapter (`faf-ice-adapter.jar`) for the FAF client without changing the client (milestone "Network improvements", issues #229–#231). It does the adapter's whole job as [LAUNCHER_ADAPTER_CONTRACT.md](LAUNCHER_ADAPTER_CONTRACT.md) describes it:

- a JSON-RPC server on `--rpc-port` for the client: the 10 methods, the 5 callbacks;
- a GPGNet server on `--gpgnet-port` for the game: `CreateLobby` when the game reports `Idle`, then `HostGame`, `JoinGame`, `ConnectToPeer`, `DisconnectFromPeer`; every message from the game goes to the client;
- one peer link per player (`src/netlink`, on libjuice) and one loopback UDP port per peer, which the game is told as `127.0.0.1:<port>`.

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
| `--stats-interval <s>` | seconds between statistics lines, default 10; 0 logs them only when a link closes (#241) |
| `--bind-address <ip>` | local address for ICE host candidates (default all interfaces) |
| `--game-address <ip>` | where the game's lobby port is reached (default 127.0.0.1) |
| `--log-file <path>` | log file; default `$LOG_DIR/faf-netbridge.log` when the launcher sets `LOG_DIR`. The log also goes to stderr |

`--bind-address` and `--game-address` are for test machines that drop UDP to sockets bound to 0.0.0.0, even over loopback (the game binds its lobby port that way). The environment variables `FAF_NETBRIDGE_BIND_ADDRESS` and `FAF_NETBRIDGE_GAME_ADDRESS` set them too, for runs through the launch shim, which passes only the launcher's arguments.

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
