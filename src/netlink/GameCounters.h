#pragma once

// Counts read from the game protocol's packets on one peer link (issue #241):
// what faf-netbridge logs per peer and the engine's network panel shows (#322).
// Engine addition, not recovered code.

#include <cstddef>
#include <cstdint>

namespace faf::netlink
{
  // Counts read from the game protocol's 15-byte header (SNetPacketHeader:
  // type +0, serial +5, sequence +9). Every packet a connection sends, resends
  // included, takes the next serial; a resent DATA packet keeps its sequence.
  struct GameCounters
  {
    // From the game, toward the peer.
    std::uint64_t sent = 0;
    std::uint64_t dataResends = 0; // DATA with a sequence number sent before
    // From the peer, toward the game.
    std::uint64_t received = 0;
    std::uint64_t lost = 0;    // serial numbers not seen (yet)
    std::uint64_t repeats = 0; // serial numbers seen twice (duplicates)
    std::uint64_t late = 0;    // older than the newest, first time seen

    void OnSent(const unsigned char* d, std::size_t n);
    void OnReceived(const unsigned char* d, std::size_t n);

    // Lost as a share of what the peer sent, in percent; 0 before anything arrived.
    [[nodiscard]] double LossPercent() const;

  private:
    bool mHaveSeq = false;
    std::uint16_t mTopSeq = 0;
    bool mHaveSerial = false;
    std::uint16_t mTopSerial = 0;
    std::uint64_t mSeenMask = 0; // bit i: serial mTopSerial - i seen
  };
} // namespace faf::netlink
