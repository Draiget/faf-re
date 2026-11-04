# FAF launcher ↔ ICE adapter contract

What the FAF client (downlords-faf-client) expects from the program it starts as its ICE adapter, and what that program owes the game and the peers. Anything that replaces FAF's Java adapter (`faf-netbridge`, the launch shim, issue #227 and its siblings under #243) has to keep every rule here.

Sources, read for this document:

| Source | Version |
|---|---|
| downlords-faf-client `IceAdapterImpl`, `IceAdapterApi`, `IceAdapterCallbacks`, `IceServerMapper` | `develop` at 5da818ba1a, launch options at 66e624f119; the installed client is 2026.4.1 |
| java-ice-adapter `IceAdapter`, `RPCHandler`, `RPCService`, `GPGNetServer`, `GameSession`, `PeerIceModule`, `PeerConnectivityCheckerModule`, `CandidatesMessage`, `CandidatePacket` | `master` at d49f9fe992 = release 3.3.14 (2025-08-11); the changes in 3.3.15 (tag at d81b88c, 2026-11-01) are in [section 9](#9-adapter-3315) |
| the shipped `natives/faf-ice-adapter.jar` (sha256 `5d1348f57d29e51c…`), read with `javap` and small probes | classes dated 2025-08-11, bundles jackson-databind 2.13.4.2, ice4j 3.0-66-g1c60acc, JJsonRpc (faforever fork) |
| FAForever/server `server/gameconnection.py` | `develop` at fa1ddac865 |

A full trace of two shipped adapters through `tools/fafclient` is in [launcher-adapter-contract/trace-2p.jsonl](launcher-adapter-contract/trace-2p.jsonl) (direct) and [trace-2p-relay.jsonl](launcher-adapter-contract/trace-2p-relay.jsonl) (`--force-relay`).

## 1. Launch

The client picks two free TCP ports (`new ServerSocket(0)`, closed again before the launch): the RPC port and the GPGNet port. It then starts:

```
<client>/jre/bin/java.exe [-XX:+UseZGC -Xms128m -Xmx512m] [-Dorg.ice4j.ipv6.DISABLED=true]
  -cp <nativeDir>/faf-ice-adapter.jar;<every client class path entry whose name contains "javafx-">
  com.faforever.iceadapter.IceAdapter
  --id <player id> --game-id <game id> --login <login>
  --rpc-port <rpc> --gpgnet-port <gpgnet>
  --access-token <OAuth token> --icebreaker-base-url <api base>/ice
  [--force-relay] [--debug-window --info-window]
```

- `-XX:+UseZGC -Xms128m -Xmx512m` come first in client `develop` since 66e624f119. The installed 2026.4.1 doesn't pass them. A replacement started by the jar never sees them, as they go to the JVM.
- `-Dorg.ice4j.ipv6.DISABLED=true` is added unless the player allowed IPv6.
- `nativeDir` comes from the system property `nativeDir` (default `lib`); the installed client sets `-DnativeDir=natives` in `faf-client.vmoptions`. It is resolved to an absolute path and is also the working directory.
- Environment: `LOG_DIR=<client log dir>/iceAdapterLogs` is added.
- Stdout and stderr are read line by line and only logged when the advanced ICE log is on. The exit code is logged; nothing else depends on it.
- The class name and jar name are fixed. A replacement either is that jar or is started by it (the launch shim, #231).
- The shipped adapter fails at start without the JavaFX jars (`NoClassDefFoundError: javafx/application/Application` from its log appender), which is why the client adds them.
- The shipped adapter has no `--access-token` or `--icebreaker-base-url` options; picocli runs with unmatched arguments allowed, so they are ignored. A replacement must also accept unknown options.

## 2. RPC connection

The client is the TCP client, the adapter the server on `--rpc-port`. The client tries `localhost:<rpc port>` up to 50 times, 250 ms apart. Right after connecting it calls `setLobbyInitMode` (`"auto"` for matchmaker games, else `"normal"`). `setIceServers` is called through `IceAdapterImpl.setIceServers(Collection<CoturnServer>)`; its caller in the client was not read, and the emulator sends it right after `setLobbyInitMode`.

When the RPC connection drops, the shipped adapter stops itself unless the game is in state `Launching` (`RPCService.close`: "Lost connection to first RPC Peer…").

### Framing

Both sides use JJsonRpc (client: micheljung fork 01a7fba5f4; adapter: faforever fork 37669e0fed). Read from the shipped jar's `JJsonPeer.run` with `javap`:

- every message is one `PrintWriter.println` of the JSON text, then `flush`;
- the reader takes one byte at a time, appends `(char)byte`, adds 1 for `{` and subtracts 1 for `}` **without tracking strings**, and parses the buffer when the count returns to 0.

Consequences for anything that writes to the client or the adapter:

- a `{` or `}` inside a JSON string breaks the framing; escape them as `{` / `}`;
- the reader turns each byte into one char, so UTF-8 text arrives mangled; write every non-ASCII character as a `\uXXXX` escape;
- the newline after each message ends up at the front of the next buffer, where the JSON parser skips it.

`tools/fafclient` reads with the same algorithm and journals a warning for every frame with a byte ≥ 0x80.

### Messages

JSON-RPC 2.0 with positional params. Client → adapter calls always carry an `id` (the client's proxy uses `sendAsyncRequest` for void methods and `sendSyncRequest` for `status`); the adapter answers each one. Adapter → client callbacks are notifications without an `id`. From the trace:

```
-> {"jsonrpc":"2.0","id":1,"method":"setLobbyInitMode","params":["normal"]}
<- {"result":null,"id":1,"jsonrpc":"2.0"}
<- {"id":2,"error":{"code":-32099,"message":"Server Error"},"jsonrpc":"2.0"}     (a handler threw)
<- {"method":"onGpgNetMessageReceived","params":["GameState",["Idle"]],"jsonrpc":"2.0"}
```

### Methods (client → adapter)

| Method | Params | Adapter behaviour (3.3.14, with 3.3.15's differences) |
|---|---|---|
| `quit` | — | stop everything, exit 0 after about 500 ms |
| `hostGame` | `mapName` string | new game session; GPGNet `HostGame mapName` to the game |
| `joinGame` | `remoteLogin` string, `remoteId` int | new game session; link to the host as answerer; GPGNet `JoinGame "127.0.0.1:<port>" login id` |
| `connectToPeer` | `remoteLogin` string, `remoteId` int, `offer` bool | link to the peer (offerer when `offer`); GPGNet `ConnectToPeer "127.0.0.1:<port>" login id`; ignored when the game is `Launching` or `Ended` |
| `disconnectFromPeer` | `remoteId` int | close the link; GPGNet `DisconnectFromPeer id`; since 3.3.15 also `onConnected` false if the peer was connected |
| `setLobbyInitMode` | `"normal"` or `"auto"` | value of the first `CreateLobby` argument (0 / 1) |
| `iceMsg` | `remoteId` int, `msg` string | `msg` is the JSON text of a `CandidatesMessage` from that peer (§5) |
| `sendToGpgNet` | `header` string, `chunks` list | GPGNet message to the game, sent once the game reached `Lobby` |
| `status` | — | returns a JSON string (deprecated) |
| `setIceServers` | list of `{urls: [string], username, credential}` | STUN/TURN servers for new links |

`setIceServers`: the client builds each entry from the API's coturn servers (`IceServerMapper`: `urls` = `URI.toString()` of each URL). The shipped adapter reads every URL with `new java.net.URI(url).getHost()`, so an opaque URI such as `turn:host:port` (no `//`) throws `hostname can't be null` and the call fails with -32099; `turn://host:port?transport=udp` works. Which form the FAF API hands out was not checked. A replacement should accept both. The shipped adapter also adds public STUN servers of its own (stun.cloudflare.com, stun.l.google.com, stun.sipgate.net in its log) and tries a telemetry websocket.

### Callbacks (adapter → client, notifications)

| Callback | Params | Client behaviour |
|---|---|---|
| `onConnectionStateChanged` | `"Connected"` / `"Disconnected"` (the game's GPGNet connection) | `Disconnected` → client calls `quit` |
| `onGpgNetMessageReceived` | `header` string, `chunks` list | forwarded to the lobby server; `GameFull` is handled by the client itself |
| `onIceMsg` | `localId`, `remoteId`, `msg` string | sent to the lobby server as `IceMsg` for `remoteId` |
| `onIceConnectionStateChanged` | `localId`, `remoteId`, state | log only. States seen: `gathering`, `awaitingCandidates`, `checking`, `connected` |
| `onConnected` | `localId`, `remoteId`, bool | log only |

## 3. Adapter ↔ game (GPGNet)

The adapter listens on `--gpgnet-port`; the client starts the game with `/gpgnet 127.0.0.1:<gpgnet port>`. Wire format: `tools/gpgnet/codec.go`. One game connection at a time; a new connection replaces the old one.

- On `GameState Idle` the adapter sends `CreateLobby <initMode 0|1> <lobby UDP port> <login> <id> 1`. The lobby port is free UDP port from 20000 up.
- `HostGame`, `JoinGame`, `ConnectToPeer`, `DisconnectFromPeer` as in the method table. Each peer gets its own loopback UDP socket; the address handed to the game is `127.0.0.1:<that port>`, and the game's datagrams to it are the link's payload.
- Every message from the game, including the ones the adapter acts on (`GameState`, `GameEnded`), goes to the client with `onGpgNetMessageReceived`.
- Messages for the game (`sendToGpgNet`, the commands above) wait until the game reported `GameState Lobby`.
- GPGNet connection lost → `onConnectionStateChanged "Disconnected"` and all links close.
- A race in 3.3.14: `GPGNetClient`'s constructor starts the listener thread before `GPGNetServer` stores the client. A game that sends `GameState` within milliseconds of connecting makes `TelemetryDebugger.gameStateChanged` throw `IllegalStateException: gameState must not change to null`, which ends the listener; that game then never gets `CreateLobby`'s follow-ups. Seen with a fake game that reports `Idle` at once (2026-10-31); the real game loads for seconds first. `faf-netbridge` handles the game's messages on one thread and has no such window.

## 4. Lobby server's part

The lobby server pairs players from the game states the client forwards (`gameconnection.py`):

- host reaches `Lobby` → `HostGame <map>` to the host;
- a joiner reaches `Lobby` → `JoinGame <host login> <host id>` to the joiner, and `ConnectToPeer <joiner> offer=true` to the host;
- then for every other player already in the game: `ConnectToPeer <other> offer=true` to the joiner and `ConnectToPeer <joiner> offer=false` to the other;
- `IceMsg <receiver id> <msg>` from a client reaches the receiver's client as `IceMsg [<sender id>, <msg>]`, which calls `iceMsg(senderId, msg)`;
- a player leaving: `DisconnectFromPeer <id>` to the others.

So the host offers to every joiner, and a joiner offers to every player who was there before it except the host.

## 5. Signalling message

`msg` of `iceMsg` / `onIceMsg` is the text of a Jackson-serialised `CandidatesMessage` record:

```json
{"srcId":101,"destId":102,"password":"6cmvb8d7e03sma550p6dtta5vn","ufrag":"eb31i1k68fj1m5",
 "candidates":[{"foundation":"1","protocol":"udp","priority":2130706431,"ip":"192.168.42.77","port":6112,
   "type":"HOST_CANDIDATE","generation":0,"id":"…","relAddr":null,"relPort":0}]}
```

- `type` is the ice4j enum name: `HOST_CANDIDATE`, `SERVER_REFLEXIVE_CANDIDATE`, `PEER_REFLEXIVE_CANDIDATE`, `RELAYED_CANDIDATE` (also defined: `LOCAL_CANDIDATE`, `STUN_CANDIDATE`). A lower-case `host` fails the parse (`InvalidFormatException`).
- The adapter parses with a default `ObjectMapper`: an unknown field fails the parse (`UnrecognizedPropertyException`), and so does a missing `candidates` (`ValueInstantiationException`). A failed parse is logged and the message dropped; the link then times out.
- Probe and output: `tmp/claude/net-layers/ref/probe/` (not in git).

## 6. Peer link (adapter ↔ adapter)

ICE (RFC 5245, ice4j) with one UDP component; the controlling agent is the offerer. Every datagram on the selected pair starts with one type byte:

- `'d'` + one game datagram;
- `'e'` + an 8-byte timestamp: the offerer sends one every second, the answerer sends each one back unchanged, and only the offerer reads them; 10 s without an answer counts as a lost link;
- anything else is logged as "Received invalid packet" and dropped.

Restart rules (`PeerIceModule`): gathering times out after 5 s; 6 s without remote candidates after sending ours counts as lost; only the offerer starts again (at once if it had been connected, else after 5 s); after 1 earlier attempt within 2 minutes no host candidates are offered, after 2 only relay candidates. The Java adapter takes its ICE ports from 6112 upward.

## 7. Emulator

`tools/fafclient` (`go run ./cmd/fafclient`) does the client's and the lobby server's part for N players on one machine and runs any adapter unchanged:

```
fafclient -players 2 -native-dir <folder with faf-ice-adapter.jar> [-exe <native adapter>[,jar,...]]
          [-force-relay] [-game-cmd "<game> /gpgnet {gpgnet} ..."] [-game-bind 127.0.0.1] [-trace t.jsonl] [-disconnect]
```

With the default `-game fake` every player's game is `tools/fakegame`, which pings each peer over the adapters 10 times a second. The run passes when every game reached `Launching` and no ping was lost during `-hold`. On the isolated test account inbound UDP to sockets bound to 0.0.0.0 is dropped, hence `-game-bind 127.0.0.1`, and a TURN server on 127.0.0.1 got no allocations from the Java adapter, hence the default `-turn-ip` of the first private IPv4 address.

Results on 2026-10-31 with two shipped adapters: direct 138 pings each way, none lost, mean RTT 0.4 ms; `--force-relay` 131 each way, none lost, only relay candidates exchanged. `-disconnect` sends `disconnectFromPeer` after the hold, so the trace shows what an adapter reports when a peer closes.

## 8. Links in the game (ours, issue #233)

Not part of FAF's contract: an extension between our game and `faf-netbridge` that the client, the lobby server and Java peers never see. Without any adapter, the launcher can talk to the game directly instead: [LAUNCHER_NATIVE_NETWORK.md](LAUNCHER_NATIVE_NETWORK.md) (issue #274). With `net_InEngineLinks 1` the game runs each peer link itself (`src/moho/net/NetlinkPeers.cpp`) and the bridge only passes the signalling. Message names and the address scheme are in `src/netlink/EngineLinks.h`.

| Direction | Message | Arguments | Meaning |
|---|---|---|---|
| game → bridge | `NetlinkHello` | version (1) | sent right after `GameState Idle`; from now on this game links itself |
| bridge → game | `NetlinkConfig` | JSON text | `localId`, `iceServers` (as `setIceServers` gave them), `forceRelay`, `bindAddress`, `duplicateMs`; again after every `setIceServers` |
| bridge → game | `NetlinkPeer` | remote id, login, offerer 0/1 | start a link; sent ahead of the `JoinGame` / `ConnectToPeer` that names its address |
| bridge → game | `NetlinkIceMsg` | remote id, JSON text | the client's `iceMsg` for that peer |
| bridge → game | `NetlinkClose` | remote id | `disconnectFromPeer`, or a new game session |
| bridge → game | `NetlinkGameEnded` | — | the game sent `GameEnded`: no more restarts |
| game → bridge | `NetlinkIceMsg` | remote id, JSON text | the bridge calls `onIceMsg(localId, remote id, text)` |
| game → bridge | `NetlinkState` | remote id, state, connected 0/1 | the bridge calls `onIceConnectionStateChanged`, and `onConnected` when connected changes |

- The address the game is given for a peer is `240.x.y.z:p`: the peer id's low 24 bits in the address (240.0.0.0/4 is reserved and never routed) and 1000 + the bits above in the port. Every player computes the same address for the same peer. The game's datagrams to it go through a peer transport (#232) into that peer's link.
- The bridge consumes these messages; the client gets none of them through `onGpgNetMessageReceived`.
- The links are the same as the bridge's (§6, `src/netlink`), so the remote side may be a Java adapter, a bridge, or another game linking itself.
- A game that never says hello (retail, or ours with `net_InEngineLinks 0`) gets none of these, and the bridge relays its datagrams as in §3.
- The bridge must see `NetlinkHello` before the client's `joinGame` / `connectToPeer`; the lobby server sends those only after the game reports `GameState Lobby`, which follows `Idle`.

## 9. Adapter 3.3.15

Read from the diff against 3.3.14. No file of the wire protocol or the RPC changed: `CandidatesMessage`, `CandidatePacket`, `PeerConnectivityCheckerModule`, `RPCHandler`, `RPCService` and `GameSession` are the same, and game data still goes as `'d'` + datagram. Its GitHub release has no jars and client `develop` still pins 3.3.14 (`iceAdapterVersion`), so players don't have it yet. To test it, build the tag with Java 25: `gradlew -Pversion=3.3.15 -PjavafxPlatform=win :ice-adapter:shadowJar`.

| Change in 3.3.15 | What it means for a replacement |
|---|---|
| `disconnectFromPeer` reports `onConnected` false for a connected peer | `faf-netbridge` does the same |
| 2 MB receive and send buffers on the game's loopback socket and on ICE sockets | `faf-netbridge` sets them on the game's socket; libjuice has its own 1 MB on ICE sockets |
| Relayed candidates are no longer paired with private, link-local or loopback remote candidates, and a failed `CreatePermission` is retried at most 5 times with backoff | Nothing to match. On a LAN test relay every relayed address is private, so this applies to tests. |
| ice4j agents are freed without the deadlock on relayed candidates | Inside ice4j only |
| Java 25 class files | Runs on the client's bundled runtime, which is already Java 25 in 2026.4.1 |

Results on 2026-11-02 and 2026-11-03 through `tools/fafclient` with fake games, 2 runs each, with `faf-netbridge` built from this change. The relay was outside the LAN (163 ms ping from the players' machine) and every player selected relay on both ends of its pair. Pings are the fake games' answered pings per player. The relay runs had 0 lost pings except one in one `bridge + 3.3.14` run:

| Players | Direct | `--force-relay` | Relay round trip |
|---|---|---|---|
| bridge + 3.3.14 | 147-148, 0 lost | 140-164, 1 lost in one run | 551-723 ms |
| bridge + 3.3.15 | 147-149, 0 lost | 148-165, 0 lost | 551-637 ms |
| 3.3.15 + bridge | 131-154, 0 lost | 140-143, 0 lost | 547-550 ms |
| bridge + bridge | 135-137, 0 lost | 133-137, 0 lost | 546-556 ms |
| 3.3.15 + 3.3.15 | 133-135, 0 lost | 146-151, 0 lost (see below) | 556-562 ms |
| 3.3.14 + 3.3.14 | 135-149, 0 lost | 144-149, 0 lost (see below) | 547-552 ms |

The launch shim with `faf-netbridge` also passed direct with the new JVM options on the Java 25 runtime, twice: 135-136 pings, 0 lost.

Two traps when testing with a relay:

- A relay on the players' own address doesn't prove relaying. TURN permissions go by IP, so the players' host sockets get through it, and even with `--force-relay` the selected pairs came out `host`. Use `fafclient -turn-server host:port -turn-user U -turn-pass P` with a relay on another machine.
- A jar opens a socket and a relay allocation per network interface. On a test machine with 10 interfaces, two 3.3.14 or 3.3.15 jars failed all 16 attempts in 240 s: the first attempt timed out on 101 host-to-relay pairs and never reached a relay-to-relay pair. The two jar rows above ran with `JAVA_TOOL_OPTIONS=-Dorg.ice4j.ice.harvest.ALLOWED_ADDRESSES=<address>` and connected on the first attempt. `faf-netbridge` has one socket per link, so it isn't affected.
