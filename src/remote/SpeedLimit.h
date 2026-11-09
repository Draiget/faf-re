#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "remote/net/Datagram.h"
#include "remote/net/GameLinks.h"

// Engine addition (plan WP10.7), not in the binary: a server-mode player's sim-speed limit. In a lockstep game each
// client times its sim beats, turns the median into a speed step (`RATE_GameRateToSpeed`: floor(10 log10(rate)),
// rate 1.0 = ten beats a second) and publishes it (`CLIMSG_IntParam`); the game runs at the lowest (`CClientManagerImpl::
// GetSimRate`). A server-mode client runs no sim; the work it does per beat is applying the server's view, so it times
// that the same way and sends the step to the server (`ESeatMessage::SpeedLimit`), which runs at the slowest playing
// seat's limit.

namespace faf::remote
{
  /** The speed steps the game-speed controls reach (`WLD_DecreaseSimRate` stops at -10, `WLD_IncreaseSimRate` at 50). */
  inline constexpr int kMinSpeedLimit = -10;
  inline constexpr int kMaxSpeedLimit = 50;

  /**
   * The speed step a beat costing `beatMs` allows, rounded down as lockstep's is (floor(10 log10(rate))); nothing costs
   * nothing (the top). Step s needs a rate of 10^(s/10): a decade's power times one of its ten steps, from a table, so
   * no host libm call reaches the objects the libm gate checks (WPL.13) and the decade steps are exact.
   */
  [[nodiscard]] inline int SpeedLimitOfBeatMs(const double beatMs)
  {
    if (!(beatMs > 0.0)) {
      return kMaxSpeedLimit;
    }
    const double rate = (1000.0 / beatMs) * 0.1;
    static constexpr double kStep[10] = {1.0, 1.2589254117941673, 1.5848931924611136, 1.9952623149688795, 2.5118864315095801,
                                         3.1622776601683795, 3.9810717055349722, 5.0118723362727229, 6.3095734448019325, 7.9432823472428150};
    static constexpr double kDecade[7] = {0.1, 1.0, 10.0, 100.0, 1000.0, 10000.0, 100000.0}; // 10^-1 .. 10^5
    int limit = kMinSpeedLimit;
    for (int step = kMinSpeedLimit; step <= kMaxSpeedLimit; ++step) {
      const int decade = (step - kMinSpeedLimit) / 10; // -10..-1 -> 0, 0..9 -> 1, ...
      if (rate >= kDecade[decade] * kStep[(step - kMinSpeedLimit) % 10]) {
        limit = step;
      } else {
        break;
      }
    }
    return limit;
  }

  /** The last beats' costs; the limit is the median's, as lockstep takes the median of its beat times. */
  class CSpeedMeter
  {
  public:
    static constexpr std::size_t kWindow = 32;

    void Add(const double beatMs) noexcept
    {
      mSamples[mNext] = beatMs;
      mNext = (mNext + 1u) % kWindow;
      mCount = std::min(mCount + 1u, kWindow);
    }

    /** Nothing before a full window: the first beats after loading cost more than the rest. */
    [[nodiscard]] std::optional<int> Limit() const
    {
      if (mCount < kWindow) {
        return std::nullopt;
      }
      std::array<double, kWindow> sorted = mSamples;
      std::nth_element(sorted.begin(), sorted.begin() + kWindow / 2, sorted.end());
      return SpeedLimitOfBeatMs(sorted[kWindow / 2]);
    }

    /**
     * Called once a view, after `Add`: the limit to report now, once it differs from the last one reported and has
     * held for a whole window of views (a machine near a step's edge would otherwise flip between two every few
     * views); nothing otherwise.
     */
    [[nodiscard]] std::optional<int> Settled()
    {
      const std::optional<int> limit = Limit();
      if (!limit) {
        return std::nullopt;
      }
      if (limit != mCandidate) {
        mCandidate = limit;
        mHeld = 0;
      }
      if (++mHeld >= kWindow && mCandidate != mReported) {
        mReported = mCandidate;
        return mReported;
      }
      return std::nullopt;
    }

  private:
    std::array<double, kWindow> mSamples{};
    std::size_t mNext = 0;
    std::size_t mCount = 0;
    std::optional<int> mCandidate;
    std::optional<int> mReported;
    std::size_t mHeld = 0;
  };

  /** `ESeatMessage::SpeedLimit`: the kind, then varint (limit + 10), so -10..50 is 0..60. */
  [[nodiscard]] inline std::vector<std::uint8_t> EncodeSpeedLimit(const int limit)
  {
    std::vector<std::uint8_t> message;
    net::ByteWriter writer(message);
    writer.Byte(static_cast<std::uint8_t>(net::ESeatMessage::SpeedLimit));
    writer.Varint(static_cast<std::uint64_t>(std::clamp(limit, kMinSpeedLimit, kMaxSpeedLimit) - kMinSpeedLimit));
    return message;
  }

  /** The limit a whole `SpeedLimit` message carries; nothing for a malformed one or one out of range. */
  [[nodiscard]] inline std::optional<int> DecodeSpeedLimit(const std::span<const std::uint8_t> message)
  {
    if (message.empty() || message[0] != static_cast<std::uint8_t>(net::ESeatMessage::SpeedLimit)) {
      return std::nullopt;
    }
    net::ByteReader reader(message.data() + 1, message.size() - 1u);
    const std::uint64_t shifted = reader.Varint();
    if (!reader.Ok() || !reader.AtEnd() || shifted > static_cast<std::uint64_t>(kMaxSpeedLimit - kMinSpeedLimit)) {
      return std::nullopt;
    }
    return static_cast<int>(shifted) + kMinSpeedLimit;
  }
} // namespace faf::remote
