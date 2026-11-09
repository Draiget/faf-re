# Launcher ↔ game without an ICE adapter (native mode)

Issue #274. With the switch `/nativenet` the game runs every peer link itself: ICE over libjuice, a link that FAF's Java ICE adapter accepts as one of its own, and WebRTC between two of our builds. The launcher starts no adapter. It talks to the game over GPGNet directly, as FAF clients did before ICE adapters existed. Without the switch nothing changes: the game talks to an adapter as described in [LAUNCHER_ADAPTER_CONTRACT.md](LAUNCHER_ADAPTER_CONTRACT.md).

This page is what a launcher needs to support the mode: downlords-faf-client (open PR [FAForever/downlords-faf-client#3590](https://github.com/FAForever/downlords-faf-client/pull/3590), behind a preference and the `fafdevelop` mod), FAForeverRustClient (not started), and `tools/seat` (mpemu) today. The lobby server needs no change.

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

## When the game crashes in a match

With `/rejoinoffer` the game can come back to its match (issue #275). There's no adapter to keep the links, so they die with the game and the returning game builds new ones. The launcher stays connected to the lobby server, doesn't report the game as ended, and:

1. **Remembers every `JoinGame` and `ConnectToPeer` for the game**, as the server sent them, and forgets a player when `DisconnectFromPeer` names them. The server sends these once and won't send them again.
2. **Keeps its GPGNet listener open**, as the returning game connects to the same port. It drops `IceMsg` for the game while none is connected. Players' links retry, so nothing is lost by that.
3. **Starts the game again** with its usual arguments plus `/rejoin <peers> <source> 0`. `<peers>` is `player id=source,...`, from the `RejoinOffer` the game sent, without the player's own entry. `<source>` is the first field of that message.
4. **On the new connection, sends without waiting:** `IceServers`, `CreateLobby` as before, then the remembered messages in their original order. The returning game sends no `GameState`, and these messages start no lobby, so the launcher can't wait for `Idle`. Every other message goes on as usual, `IceMsg` in both directions included.

The lobby server needs no change: it routes `IceMsg` by player, and the player's connection never closed.

## Telling our exe from the original

In FAF both files are `ForgedAlliance.exe`, and the x86 build is 32-bit like the original, so a launcher reads the exe's version resource (issue #314, `src/moho/app/MohoVersion.rc`):

| Field | Our exe | The original |
|---|---|---|
| `ProductName` | `faf-re` | `Supreme Commander Forged Alliance` |
| `ProductVersion`, `FileVersion` | the release tag, for example `2026.11.001` or `2026.11.001-nightly`; any other build has its commit, for example `7104a74` | `1, 5, 0, 1` |
| numeric file version | `2026.11.1.0` for that tag; `0.0.0.0` for other builds | `1.5.0.1` |

A launcher checks `ProductName` only, under the string table `040904b0`. On Windows it is `VerQueryValue` with `\StringFileInfo\040904b0\ProductName` (JNA's `Version` in Java). A launcher that also runs on Linux, where the game runs under Wine, reads it from the file's resource section instead.

## Game command line

| Option | Meaning |
|---|---|
| `/nativenet` | native mode (the console variable `net_NativeNet 1` does the same) |
| `/nativenetrelay` | only TURN-relayed candidates: the client's "force relay" setting, or the API session's `forceRelay` |
| `/nativenetbind <address>` | ICE host candidates use this local address. Optional; for machines that drop loopback UDP to sockets bound to every interface |

`net_NativeNetWebRtc` (default 0; 1 enables it) offers a WebRTC data channel to peers that are our builds too (#239). A channel opens only when both sides offer it. It stays off because raw ICE with the lane came out ahead in the comparison posted on PR #277. `net_NativeNetRedundancy` (default 2) carries game datagrams to those peers on the redundant lane, each repeated up to that many times until acked (#240). `net_NativeNetEncrypt` (default 1; 0 turns it off) encrypts that lane with peers that offer it too, with keys agreed per connection from public keys in the ICE ufrag (#289, [NETBRIDGE.md](NETBRIDGE.md#lane-encryption-289)). A Java adapter peer keeps the plain ICE link; an older build of ours gets the lane unencrypted.

## Inside the game

`src/moho/net/NetlinkPeers.cpp` (`NATIVENET_*`), on top of the in-engine links of #233:

- `CGpgNetInterface::PullTask` passes each launcher message to `NATIVENET_HandleCommand` first.
  - `IceServers` and `IceMsg` are taken there.
  - The server's `JoinGame [login, id]` and `ConnectToPeer [login, id, offer]` start the link. They are then rewritten to the shipped form `[address, login, id]` with the peer's engine address (`240.x.y.z:p`, `src/netlink/EngineLinks.h`), so the lobby script runs unchanged.
  - `DisconnectFromPeer` closes the link; `HostGame` and `JoinGame` start a new session.
- `CreateLobby` gives the game its own player id for the links.
- Signalling from a link goes out as `IceMsg [receiver id, text]`.
- When the game sends `GameEnded`, links stop restarting.

## Network panel

With no adapter there is no adapter window, so the game shows its links itself and lets the player act on them (#322): `net_ShowPanel 1`, or Ctrl+Shift+F11 in the game window (F11 alone stays FAF's connectivity screen). The renderer draws it in the same pass as the debug overlays (`src/moho/app/NetworkPanel.cpp`), so it shows in the lobby, on the loading screen and in a game, over Direct3D 11, 12 and Vulkan. Mouse presses on the panel go to the panel, with the release that ends them; the game never sees them, and moves still reach it. Its text is Consolas from Windows' fonts folder, drawn from an MSDF atlas like the interface's text; without that file it is Courier New through GDI.

Along the top: **Copy diagnostics** (the build, every link with its counts, the log file's path and the network log lines), **Log folder**, and **X** to close. Three tabs:

- **Peers**: one row per peer.

  | Column | From |
  |---|---|
  | state | the link's state (`LinkStateName`); `#n` after the n-th connection attempt |
  | path | `direct` or `relayed`, then the selected pair's candidate types, local/remote (`host`, `srflx`, `prflx`, `relay`) |
  | round trip | the offerer's echo; on the answerer, which sends no echo, the lane's smoothed RTT |
  | loss, resends | the game protocol's own counts on this link (`src/netlink/GameCounters.h`, as faf-netbridge's statistics lines): serial numbers that never arrived, and DATA packets the game sent again |
  | lane | `encrypted`, `plain` or `off` (#240, #289) |
  | picked | the path picked for this link: `auto`, `relay only`, `relay via host:port` or `no relay` |

  A click on a row selects the peer. Under the table: **Reconnect** (as the link is), **Auto**, **Relay only**, **No relay**, and **Relay via** one button per TURN server. Each reconnects the link on that path and keeps it for the link's later attempts. Auto is FAF's adapter policy: every candidate type on the first attempt, no host candidates after one attempt within 2 minutes, relayed only after two. A picked path holds over that policy and starts it afresh. With `/nativenetrelay` the game takes relayed candidates only, and No relay is greyed out.
- **Log**: the game log file's path and the last 200 `NETLINK:` and `NET:` lines, 18 at a time; the mouse wheel and **Older** / **Newer** scroll, **Copy log** copies them.
- **ICE servers**: the TURN and STUN servers new links use (from `IceServers`), with **Every peer through this relay** per TURN server, and Auto, Relay only or No relay for every peer at once.

**Log folder** opens Explorer with the log file selected (`SHOpenFolderAndSelectItems`). When the shell refuses, for example for a game run as another Windows user than the desktop's, the log file's path goes on the clipboard and the panel says so.

Each end of a link filters candidates by its own attempt history, the peer's included, so a path picked on one end alone could lose to the other's policy. The pick therefore travels with the candidates: a `fafPath` field (`auto`, `relay` or `norelay`) in the `IceMsg` JSON, sent only to a peer whose ufrag carries our prefix, since the Java adapter rejects unknown fields. Our peer follows it for that attempt; `auto` restarts its policy once. Older builds of ours ignore the field.

With in-engine links behind faf-netbridge (#233) the panel shows the same; with the launcher's adapter running the links it says so, since the game has no links of its own then.

## Tray icon

With no adapter there is no adapter tray icon either, so the game shows one while it runs its own links (#321, `src/moho/app/NetworkTray.cpp`, switch `net_TrayIcon`). It comes with the first link setup (native mode or in-engine links) and goes when GPGNet shuts down or the game exits. Its tooltip counts links up, relayed and lost. A click opens its menu:

- one line per peer: state, path and round trip, as on the panel;
- **Network panel**: shows or hides the panel, as Ctrl+Shift+F11 does;
- **Reconnect**: drops the link to one peer and connects again. The offerer offers again at once; when the answerer asks, the offerer notices within 10 s, when its echo goes unanswered. A new attempt within 2 minutes of another offers no host candidates, as the Java adapter does;
- **Open log folder**: Explorer with the game's `/log` file selected; when the shell refuses, the path goes on the clipboard and a notification says so;
- **Copy diagnostics**: the build, every link with its counts, the log file's path and the latest network log lines, for a bug report.

The icon has its own thread and window, so the menu works while the game window is minimised after alt-tab.

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
