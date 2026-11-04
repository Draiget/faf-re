# Launcher ↔ game without an ICE adapter (native mode)

Issue #274. With the switch `/nativenet` the game runs every peer link itself: ICE over libjuice, a link that FAF's Java ICE adapter accepts as one of its own, and WebRTC between two of our builds. The launcher starts no adapter. It talks to the game over GPGNet directly, as FAF clients did before ICE adapters existed. Without the switch nothing changes: the game talks to an adapter as described in [LAUNCHER_ADAPTER_CONTRACT.md](LAUNCHER_ADAPTER_CONTRACT.md).

This page is what a launcher needs to support the mode: downlords-faf-client and FAForeverRustClient, through later PRs, and `tools/seat` (mpemu) today. The lobby server needs no change.

## What the launcher does

1. **Hosts GPGNet itself.** It listens on a local TCP port and starts the game with `/gpgnet 127.0.0.1:<port> /nativenet` and its usual arguments. No adapter process, no JSON-RPC.
2. **On the game's `GameState Idle`**, it sends:
   - `IceServers [json]`: the TURN/STUN list for this game, as a JSON text. The game accepts a list of `{urls, username, credential}` (the Java client's `IceServerMapper` shape; `urls` may be a list or a single string, `url` works too). It also accepts the API's ICE session object with the list under `servers` (the Rust client passes it on unmapped). URLs may be `turn:host:port` or `turn://host:port`, with `?transport=udp|tcp`.
   - `CreateLobby [init mode, port, login, id, 1]`, as the adapter sends it today: init mode 1 for matchmaker games, else 0; the port may be 0.

   It sends `IceServers` again if the list changes. Links started afterwards use the new list.
3. **Forwards every lobby-server message for the game unchanged.** These are the messages the server sends with `"target": "game"`, with the arguments as the server sends them:

   | Message | Arguments | What the game does |
   |---|---|---|
   | `HostGame` | map | a new game session |
   | `JoinGame` | login, id | a new game session; a link to the host as answerer |
   | `ConnectToPeer` | login, id, offer | a link to that player, offerer when `offer` is 1 |
   | `DisconnectFromPeer` | id | closes the link |
   | `IceMsg` | sender id, text | that player's signalling, for its link |

   GPGNet has no booleans: `offer` goes as an int (0 or 1).
4. **Forwards every game message to the lobby server**, as the adapter's `onGpgNetMessageReceived` messages are forwarded today. That includes the game's signalling, `IceMsg [receiver id, text]`. The server already routes it: `GameConnection.handle_ice_message` sends it to the receiver's game as `IceMsg [sender id, text]` (faf-server `server/gameconnection.py:465-485`). The launcher does nothing special with it.

That is the whole contract. The game never sends the adapter's callbacks: it has no `onIceConnectionStateChanged` or `onConnected` for the launcher. Link states are in the game log (`NETLINK: peer …`).

## Game command line

| Option | Meaning |
|---|---|
| `/nativenet` | native mode (the console variable `net_NativeNet 1` does the same) |
| `/nativenetrelay` | only TURN-relayed candidates: the client's "force relay" setting, or the API session's `forceRelay` |
| `/nativenetbind <address>` | ICE host candidates use this local address. Optional; for machines that drop loopback UDP to sockets bound to every interface |

`net_NativeNetWebRtc` (default 0; 1 enables it) offers a WebRTC data channel to peers that are our builds too (#239). A channel opens only when both sides offer it. It stays off because raw ICE with the lane came out ahead in the comparison posted on PR #277. `net_NativeNetRedundancy` (default 2) carries game datagrams to those peers on the redundant lane, each repeated up to that many times until acked (#240). A Java adapter peer, or an older build, keeps the plain ICE link.

## Inside the game

`src/moho/net/NetlinkPeers.cpp` (`NATIVENET_*`), on top of the in-engine links of #233:

- `CGpgNetInterface::PullTask` passes each launcher message to `NATIVENET_HandleCommand` first.
  - `IceServers` and `IceMsg` are taken there.
  - The server's `JoinGame [login, id]` and `ConnectToPeer [login, id, offer]` start the link. They are then rewritten to the shipped form `[address, login, id]` with the peer's engine address (`240.x.y.z:p`, `src/netlink/EngineLinks.h`), so the lobby script runs unchanged.
  - `DisconnectFromPeer` closes the link; `HostGame` and `JoinGame` start a new session.
- `CreateLobby` gives the game its own player id for the links.
- Signalling from a link goes out as `IceMsg [receiver id, text]`.
- When the game sends `GameEnded`, links stop restarting.

## Change points in the launchers

From reading both clients (Java: downlords-faf-client `develop` 66e624f119; Rust: FAForeverRustClient `develop` 70c88a5f9b, both 2026-10-31):

- **downlords-faf-client.** Implement a second `IceAdapter` (`fa/relay/ice/IceAdapter.java`), chosen by a preference.
  - Its `start` opens the GPGNet listener and returns its port. `LaunchCommandBuilder` already writes `/gpgnet` from that port; add `/nativenet` beside it.
  - Move the lobby subscriptions in `IceAdapterImpl.java:81-111` behind the choice, so only one implementation forwards.
  - The client has no GPGNet codec today, so one is needed. The adapter jar's `GPGNetServer` is the reference; `tools/gpgnet/codec.go` in this repository is another.
  - `GameFull` stays handled in the client. Every other game message goes to the server, `IceMsg` included.
- **FAForeverRustClient.** Add a fourth adapter kind (`connectivity.rs:14-28`, `ice_select.rs`, `infra/mod.rs:921-927`), built from the Go backend's pieces:
  - the GPGNet codec;
  - `CreateLobby` on `Idle` (`ice_pioneer.rs:257-273`);
  - the lobby-to-GPGNet mapping (`:345-390`), which must keep `IceMsg` and `offer` instead of dropping them;
  - the ICE session fetch in `ice_java.rs:1040`, sent to the game as `IceServers`.

  Game messages already reach the server unchanged (`ice_pioneer.rs:249-286`).

## Testing

mpemu plays this launcher with `contract: {adapter: native}`, or `adapter: native` on one player of a contract-mode game (`tools/seat/native.go`). It relays `IceMsg` between seats the way the server does, to native and adapter seats alike, so one game can mix the two. `contract.iceServers` hands out a TURN server running elsewhere instead of mpemu's own; its fields expand environment variables, so a scenario file holds no address.
