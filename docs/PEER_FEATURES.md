# Peer features

Some features only work when every player in a game runs our engine. This page is the one place that says which features those are, how players learn what each other supports, and how to add one. Issue #285.

Don't add another way to detect our builds, or a new message type for a feature. Add an entry here.

## How it works

With `net_PeerFeatures 1`, each client sends one `CLIMSG_PeerFeatures` message (type 58) to every peer as its game finishes loading. It says which features this client supports and which build it is. A client that never announces supports nothing, which is how a retail client looks.

The message travels on the ordered game link, so it works on every kind of link: direct, relay, ICE adapter or native. Nothing enters the command stream, so the sim and replays never see it.

To ask, use `mPeerFeatures` on the client manager, under its lock:

```cpp
manager.mPeerFeatures->EveryoneSupports(manager, EPeerFeature::OrderStreamCheck); // this client and everyone still in the game
manager.mPeerFeatures->PeerSupports(clientIndex, EPeerFeature::OrderStreamCheck); // one client
```

## In the lobby

A game link only exists once a game has begun, so while players are still in the lobby the same announcement travels as a lobby message: `LOBMSG_PeerFeatures` (type 112), with the same format as below. Each client sends it to a player as their lobby link is established, with `net_LobbyPeerFeatures` on, which is the default. Having received one is what says that player runs our engine: `CLobbyPeerFeatures::PeerRunsOurEngine` in `src/moho/net/LobbyPeerFeatures.h`.

Feature traffic for the lobby goes in this message with a first byte other than 0, as it does in the game.

## Features

| Feature | Bit | Announced when | What it means |
|---|---|---|---|
| `OrderStreamCheck` | 0 | `net_CheckOrderStreams` was on as the game began | This client's acks carry `CommandStreamCheck`'s hash after their fields. With `net_PeerFeatures` on, a peer's hash is compared only once it announced this; off, the ack's size says it, as before |
| `SkewCorrection` | 1 | `wld_SkewCorrection` was on as the game began | This client's display clock keeps to real time; the correction only runs when every player announces this |
| `FastAck` | 2 | `net_FastRetransmit` was on as the game began | This client acknowledges within `net_FastAckDelay`, which the shared start takes off that peer's ping |
| `SignedStyle` | 3 | In the lobby, when this client has a valid style key | This client answers a style challenge |
| `Rejoin` | 4 | `net_RejoinAccept` is on | A client that restarts can take its seat back (#275). With any client that didn't announce it, a lost link behaves as in the original game |

`SignedStyle` is announced only in the lobby. A player who announces it can prove a style with a key: the other player sends a random challenge (kind 1), and the answer (kind 2) is the colour with a signature over both players' ids, the challenge and the colour (`src/remote/net/StyleProof.h`). The engine keeps only the public key. The key file is `peer_style.key` beside the exe, or `/peerstylekey <file>`: the seed in hex, then the colour as `rrggbb`. A proven colour shows on the player's name in the lobby: the engine wraps the lobby script's `SetSlotInfo` (`CLobbyPeerFeatures::InstallSlotStyles`), with no script file of its own.

## Adding a feature

1. Add one entry to `EPeerFeature` in `src/moho/net/PeerFeatures.h`, with the next unused bit. Bits never change or get reused, because other builds read them.
2. Set its bit in `CPeerFeatures::LocalMask`, so a client only announces what this session really does.
3. Add a row to the table above.
4. Before you use it, ask `EveryoneSupports` or `PeerSupports`.
5. Send the feature's own messages as `CLIMSG_PeerFeatures` with a first byte other than 0, not as a new message type. Only types 58 and 59 are free below the client range's end of 60, and 59 is kept in reserve.

A feature that changes what the sim computes is not covered by this page. [CONTRIBUTING.md](../CONTRIBUTING.md) rule 1 applies to it.

## Message format

All integers are little-endian.

| Bytes | Field | Meaning |
|---|---|---|
| 1 | kind | 0: announcement. Other values are feature traffic (1 to 8: rejoin), and a client that doesn't know one ignores it |
| 1 | format | 1 |
| 8 | mask | One bit per `EPeerFeature`. A bit this build doesn't know is ignored |
| rest | build | Short commit hash, NUL-terminated. A later format adds its fields after this |

## Retail clients

A retail client gets one small message per game from each of our clients that has the switch on. From reading the binary: `CNetClient`'s constructor registers the client range up to 60 (`0x0053BBE2` pushes `0x3C`), and `CClientBase::Process` logs `CClientBase::Queue(): Ignoring message type 58` (`0x0053C2E0`) and returns. `net_PeerFeatures` is off by default until the compatibility matrix (#242) has passed with it.

In the lobby a retail client gets one small message from each of our clients. From reading the binary: the jump table at `0x007C6454` sends type 112 to `LOBBY: Ignoring unrecognized lobby message` (`0x007C6412`), which logs and returns. It never announces, so it gets nothing more.

## Other mechanisms, and why they stay

| Mechanism | Purpose | Why it isn't this |
|---|---|---|
| ICE ufrag prefix `fnl+` plus a probe (#234, `src/netlink/Link.h`) | Link setup: WebRTC and the net channel between our peers | It has to decide before a game link exists |
| `NetlinkHello` ([NETBRIDGE.md](NETBRIDGE.md)) | The game telling its local bridge it runs the links | It isn't sent to peers |
| `SWireHello` (`src/remote/wire/WireVersion.h`) | Client and dedicated server | It decides whether the two can play at all, with no negotiation |
