#include "netlink/GameCounters.h"

namespace faf::netlink
{
  namespace
  {
    constexpr unsigned char kPacketData = 4; // PT_Data
    constexpr unsigned char kPacketTypes = 9; // PT_Connect .. PT_NATTraversal
    constexpr std::size_t kHeaderSize = 15;  // kNetPacketHeaderSize

    std::uint16_t U16(const unsigned char* p) { return static_cast<std::uint16_t>(p[0] | (p[1] << 8)); }
    // Serial and sequence numbers wrap at 16 bits.
    std::int32_t Diff16(const std::uint16_t a, const std::uint16_t b) { return static_cast<std::int16_t>(a - b); }
  } // namespace

  void GameCounters::OnSent(const unsigned char* d, const std::size_t n)
  {
    ++sent;
    if (n < kHeaderSize || d[0] != kPacketData) {
      return;
    }
    const std::uint16_t seq = U16(d + 9);
    if (mHaveSeq && Diff16(seq, mTopSeq) <= 0) {
      ++dataResends;
      return;
    }
    mHaveSeq = true;
    mTopSeq = seq;
  }

  void GameCounters::OnReceived(const unsigned char* d, const std::size_t n)
  {
    ++received;
    if (n < kHeaderSize || d[0] >= kPacketTypes) {
      return;
    }
    const std::uint16_t serial = U16(d + 5);
    if (!mHaveSerial) {
      mHaveSerial = true;
      mTopSerial = serial;
      mSeenMask = 1;
      return;
    }
    const std::int32_t ahead = Diff16(serial, mTopSerial);
    if (ahead > 0) {
      // Everything skipped counts as lost until it turns up late.
      const auto shift = static_cast<std::uint64_t>(ahead);
      lost += shift - 1;
      mSeenMask = shift >= 64 ? 1 : (mSeenMask << shift) | 1;
      mTopSerial = serial;
      return;
    }
    const auto back = static_cast<std::uint64_t>(-ahead);
    if (back >= 64) {
      ++late; // too old to tell apart
      return;
    }
    if ((mSeenMask >> back) & 1) {
      ++repeats;
      return;
    }
    mSeenMask |= std::uint64_t{1} << back;
    ++late;
    if (lost > 0) {
      --lost; // counted missing when a newer one came first
    }
  }

  double GameCounters::LossPercent() const
  {
    const std::uint64_t expected = received - repeats + lost;
    return expected > 0 ? 100.0 * static_cast<double>(lost) / static_cast<double>(expected) : 0.0;
  }
} // namespace faf::netlink
