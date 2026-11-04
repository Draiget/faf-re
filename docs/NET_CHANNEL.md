# Net channel

`src/remote/net` is the transport the dedicated server will speak to its clients, and that links between two of our engines will use (issue #240). It is the plan's D1 design (`.plans/dedicated-server/PLAN.md` §7.1): UDP datagrams carrying a reliable ordered stream and unreliable messages, with acks, resends, keepalives, statistics and authenticated encryption. No third-party networking library; the only external piece is Monocypher for the encryption.

The library does no I/O and reads no clock. Its owner passes each arriving datagram to `NetChannel::Receive` with the time, calls `NetChannel::Poll` with the time to collect the datagrams to send, and moves them over any carrier (a UDP socket on the server, the game's own link between peers). Times are microseconds on one monotonic clock of the owner's choice. That keeps the channel deterministic: the tests drive two channels over a simulated link and get the same result on every platform.

It is a static library, `faf_netchannel`, with no engine dependency, built in every configuration (Windows x64 and x86, Linux). Tests: `faf_netchannel_tests`.

```powershell
cmake --build --preset clang-x64-release --target faf_netchannel_tests
build\clang-x64-release\tests\remote\faf_netchannel_tests.exe   # exit code = failures
```

## Datagram (WP10.2, #141)

At most 1,200 bytes: a 16-byte header, then chunks, then (once encrypted) a 16-byte tag. All integers are little-endian; varints are LEB128.

| Bytes | Field |
|---|---|
| 0 | `0xFC`; anything else is not a channel datagram |
| 1 | flags: bit 0 encrypted, bit 1 ack-only (the receiver does not ack it back); other bits refuse the datagram |
| 2–5 | sequence: 1, 2, 3, … per direction; 0 is never sent. A channel that reaches 2³²−1 fails instead of wrapping |
| 6–9 | ack: the newest sequence received from the peer (0 before the first) |
| 10–13 | ack bits: bit i set when sequence ack − 1 − i was received |
| 14–15 | ack delay: time from receiving `ack` to sending this datagram, in 100 µs units |

Chunks:

| Type | Layout | Use |
|---|---|---|
| 1 reliable | varint stream offset, varint length (≥ 1), bytes | a piece of the reliable stream |
| 2 unreliable | varint length, bytes | one unreliable message |
| 3 acks | varint block count (1–16), then per block: varint (header ack − block top), 4 bytes of bits (bit i: sequence top − i received) | acks for a burst larger than the header's 33 sequences |

The plan's header (§7.1) also lists the acknowledged frame id and, every N ticks, an 8-byte frame hash. Both belong to the snapshot lane (WP10.4, WPR.30) and will travel in its own chunk type, so datagrams without a snapshot (commands, acks, keepalives) don't carry them. The reliable stream's state is the offsets in its chunks.

Per datagram the overhead is 32 bytes of channel (header and tag) plus 28 of IP and UDP, 60 in all with encryption. The plan's traffic model (§7.2) counts 44, without the tag.

The receiver keeps the last 1,024 sequences: a sequence seen before is dropped as a duplicate or replay, one older than the window as too old. A datagram is authenticated and fully parsed before anything is recorded, so a broken or forged datagram changes no state. A datagram that acks a sequence the channel never sent is malformed.

## Reliable stream (WP10.3, #142)

Messages are laid end to end in one byte stream per direction, each a varint length and its bytes, so a message of any size (up to `maxMessageSize`, 16 MiB by default) spans as many datagrams as it needs. The sender keeps every byte until a datagram carrying it is acked. When a datagram is counted lost, its ranges go back on the queue minus whatever another datagram already delivered, and a resend may cut the stream differently from the first send. Lost ranges go out before new bytes, and new bytes only while the bytes past the peer's acked prefix stay within `maxReliableInFlight` (256 KiB).

The receiver puts fragments back in stream order, drops bytes it already has, and holds out-of-order bytes up to `receiveWindow` (1 MiB) past what it has delivered; a fragment beyond that is dropped and comes back on a resend. A message announcing more than `maxMessageSize` fails the channel.

Redundant messages (`SendRedundant`, chunk type 4: varint lane sequence, varint length, bytes) are unreliable messages that ride again in later datagrams, up to `redundancy` (2) more times each, until a datagram carrying them is acked. With nothing new to send, `Poll` repeats unacked ones at most every `redundantRepeatUs` (30 ms). The receiver hands each lane sequence out once, through `TakeUnreliable`, and drops repeats. Peer links between our builds carry game datagrams this way (issue #240, [NETBRIDGE.md](NETBRIDGE.md)). In the tests, at 20 % loss each way with a message every 33 ms, 78.4 % arrive with no repeats and 98.92 % with redundancy 2.

Unreliable messages fit one datagram each (`MaxUnreliableSize()`, 1,181 bytes without encryption), go out before reliable bytes, are never resent, and arrive at most once.

## Acks, loss and RTT (WP10.8, #147)

- An ack goes out within `ackDelayUs` (10 ms) of an arrival when nothing else is sent, and at once after a gap, a late arrival, or 4 unanswered datagrams. Ack-only datagrams are not acked back.
- A datagram counts as lost when one sent `lossThreshold` (3) later is acked, when it is older than 9/8 RTT and a later one is acked, or when it is older than the retransmission timeout. A late ack takes the loss back (`spuriousLosses`) and widens the reordering allowance: the count to the distance seen (up to 64), the time by 1/8 RTT (up to 2 RTT). Paths that reorder then stop causing resends.
- RTT comes from the newest acked datagram, less the delay the peer reports (up to `maxAckDelayUs`, 25 ms), smoothed as RFC 6298 does. The retransmission timeout is SRTT + max(4 × RTTVAR, 1 ms) + `maxAckDelayUs`, kept within 50 ms–2 s, and doubles for each timeout in a row (up to 64×) until something is acked, so a dead link is not flooded.
- A keepalive goes out when no ack-eliciting datagram was sent for `keepaliveIntervalUs` (250 ms), so an idle link keeps measuring RTT and both ends keep hearing each other.
- The channel times out when nothing arrives for `timeoutUs` (10 s). `State()` turns `TimedOut`, sending and receiving stop, and the server's disconnect handling (WP3.5) reads that. `SinceLastReceivedUs()` gives the silence so far.

`Stats()` reports datagrams and bytes each way; ack-only datagrams and keepalives sent; duplicates, too-old, malformed and unauthenticated datagrams dropped; datagrams acked, lost and spuriously lost; reliable bytes resent; the lost share of the last 256 datagrams; the peer's sequences missing and reordered; and RTT latest, smoothed, variation, minimum, samples and the current timeout.

## Encryption (WP10.6, #145)

After the handshake (WP10.5) gives the channel one key per direction, `SetKeys` turns on XChaCha20-Poly1305 for every datagram both ways. It works once per channel and refuses a second call. Each end calls it when it has the keys. Datagrams the other end sends unsealed in between are dropped, and the losses are made good like any others. The header stays readable and is the associated data, so the tag covers it as well. The payload is encrypted in place and the tag follows it. The nonce is the sequence number, which never repeats under one key, because each direction has its own key, a channel never reuses a sequence, and the handshake makes new keys per channel. A reconnect is a new channel, starting again at sequence 1, so it must have new keys. The channel can't detect a reused key, so that rule falls on WP10.5. With keys set, a datagram that is not sealed, or whose tag does not match, is dropped before anything else reads it. Replays pass the tag but are dropped by the receive window. Keys are wiped when the channel is destroyed.

Without keys the channel trusts its path. Anyone who can put a datagram on it can ack data that never arrived, or inject stream bytes. A channel between players has keys before game data flows over it.

The primitive is Monocypher 4.0.2 ([monocypher.org](https://monocypher.org)), dual-licensed BSD-2-Clause or CC0 at the user's choice. It is one C file, pinned by SHA256 in `cmake/FafDependencies.cmake`, built by `cmake/deps/monocypher`. The same file has X25519 for the handshake. A tree without the download (configured with `FAF_FETCH_DEPENDENCIES=OFF`, or fetched before this dependency existed) builds without the channel and says so at configure time.

## Tests

`tests/remote/net/NetChannelTests.cpp` runs two channels over a simulated link, stepped 1 ms at a time, with latency, jitter (which reorders), loss, duplication and partitions, from one seeded random stream. It checks:

- the header and the receive window against a plain model;
- the range set against a model;
- reassembly from shuffled, overlapping fragments;
- reliable delivery both ways in order over seven links from clean to 50 % loss and from 0 to 50 ms jitter with 10 % duplication;
- the in-flight limit;
- that unreliable messages arrive at most once and intact;
- sealing, including every single-bit change;
- known answers: the XChaCha20-Poly1305 test vector of draft-irtf-cfrg-xchacha-03 (A.3.1), and the channel's own layout against bytes libsodium produced;
- keys set mid-session, at different moments on the two ends, with data in flight;
- the encrypted channel against tampering, replay, plaintext and keys on one side only;
- keepalives and RTT on an idle link;
- loss statistics at 10 % loss;
- timeout after a 12 s partition and none after a 2 s one (the server's use of the timeout, WP3.5, is not written yet);
- backoff during a partition;
- 200,000 fuzzed datagrams with and without keys.

Windows x64, Windows x86 and Linux give byte-identical output.

Not covered yet: sockets (WP10.1, #140), the handshake that makes the keys (WP10.5), rate control (WP10.7) and the `tools/relay` matrix over real sockets (WP10.11).
