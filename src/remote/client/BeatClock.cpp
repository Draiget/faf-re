#include "remote/client/BeatClock.h"

#include <algorithm>
#include <cmath>

// Engine addition, server mode: see BeatClock.h.

namespace faf::remote::client
{
  namespace
  {
    constexpr double kSmoothing = 0.1; // weight of a new sample in the running rates
  } // namespace

  void CBeatClock::OnFrame(
    const std::uint32_t beat, const std::int32_t simRate, const std::uint32_t serverMs, const double localSeconds
  ) noexcept
  {
    if (mFrames != 0u && beat > mLastBeat) {
      const double beats = static_cast<double>(beat - mLastBeat);
      const double serverSeconds = static_cast<double>(serverMs - mLastServerMs) / 1000.0;
      const double localElapsed = localSeconds - mLastLocal;
      if (serverSeconds > 0.0) {
        const double sample = beats / serverSeconds;
        mServerRate = mServerRate == 0.0 ? sample : mServerRate + kSmoothing * (sample - mServerRate);
      }
      if (localElapsed > 0.0) {
        const double sample = beats / localElapsed;
        mArrivalRate = mArrivalRate == 0.0 ? sample : mArrivalRate + kSmoothing * (sample - mArrivalRate);
      }
    }
    ++mFrames;
    mLastBeat = beat;
    mLastServerMs = serverMs;
    mLastLocal = localSeconds;
    mSimRate = simRate;
  }

  double CBeatClock::ExpectedBeatsPerSecond() const noexcept
  {
    return kBeatsPerSecondAtRate0 * std::pow(10.0, static_cast<double>(mSimRate) / 10.0);
  }

  std::int64_t CBeatClock::Backlog() const noexcept
  {
    return mFrames != 0u ? static_cast<std::int64_t>(mLastBeat) - static_cast<std::int64_t>(mShownBeat) : 0;
  }

  double CBeatClock::Skew() const noexcept
  {
    // Fewer beats held than the target: slow down (positive); more: hurry (negative).
    const std::int64_t off = mTargetBacklog - std::max<std::int64_t>(Backlog(), 0);
    return static_cast<double>(std::clamp<std::int64_t>(off, -4, 4)) * 0.5;
  }
} // namespace faf::remote::client
