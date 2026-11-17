#pragma once
// Engine addition (net_LagAuto, off by default), not in the binary: the order delay (net_Lag) from the round trip to
// the slowest peer instead of a fixed 500 ms, for players on good links who switch it on.
//
// A client's delay only has to cover how late its own beats reach the others, which only the others see. Two inputs
// a client sees alone were tried in two-client test games (docs/NETWORK_MEASUREMENTS.md) and both pulled the
// clients' delays apart: the other players' beats timed against this client's own sending (that timing holds the
// difference between the two delays, so each change fed the other's), and pauses (only the player who waits pauses;
// the player whose beats came late carries on). What is left is the round trip, the same in both directions: the
// delay is half its 99th percentile over the last 30 s plus a margin, between net_LagMin and net_LagMax. It drops
// slowly and rises at once. Delays the peers report would do better, through the shared peer announcement
// (net_PeerFeatures), which is off by default.
//
// Only when beats are sent changes. What a beat holds and the beat an order runs in are recorded in the replay as
// they happened, so replays play the same.

namespace moho
{
  /// The slowest round trip to a peer right now, in ms (0: no peer); once per newly available beat.
  void NET_LagNotePing(float maxPingMs);

  /// The order delay to pace with now, in ms: net_Lag when net_LagAuto is 0 or nothing was measured yet.
  [[nodiscard]] float NET_LagCurrentMs();

  /// Forget everything (a new game).
  void NET_LagReset();
} // namespace moho
