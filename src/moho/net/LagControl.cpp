#include "LagControl.h"

#include "gpg/core/utils/Logging.h"
#include "moho/console/CConCommand.h"
#include "moho/net/NetConVars.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <mutex>
#include <vector>

namespace moho
{
  namespace
  {
    using Clock = std::chrono::steady_clock;

    // 30 s of beats at the normal rate; the 99th percentile of them is the 3rd largest.
    constexpr std::size_t kWindowBeats = 300;
    // Fewer than this and the delay stays at net_Lag.
    constexpr std::size_t kMinSamples = 100;
    // Above half the round trip: jitter, a lost beat's repair, the sender's own scheduling.
    constexpr float kMarginMs = 100.0f;
    // It comes down this much at a time, at most every kDropEveryMs; it rises to its target at once.
    constexpr float kDropStepMs = 25.0f;
    constexpr std::int64_t kDropEveryMs = 2000;
    // How often the target is worked out again.
    constexpr std::int64_t kRecomputeEveryMs = 500;

    struct State
    {
      std::mutex mutex;
      std::vector<float> pings; // ring of the slowest peer's round trip per beat (ms)
      std::size_t next = 0;
      bool started = false;
      float currentMs = 0.0f;
      Clock::time_point lastChange{};
      Clock::time_point lastRecompute{};
      float loggedMs = -1.0f;
    };

    State& S()
    {
      static State s;
      return s;
    }

    std::int64_t MsBetween(
      const Clock::time_point a,
      const Clock::time_point b
    )
    {
      return std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count();
    }

    float Percentile99(
      std::vector<float> values
    )
    {
      const std::size_t i = std::min(values.size() - 1, (values.size() * 99 + 99) / 100 - 1);
      std::nth_element(values.begin(), values.begin() + static_cast<std::ptrdiff_t>(i), values.end());
      return values[i];
    }
  } // namespace

  void NET_LagNotePing(
    const float maxPingMs
  )
  {
    if (maxPingMs <= 0.0f) {
      return;
    }
    State& s = S();
    std::scoped_lock lock(s.mutex);
    if (s.pings.size() < kWindowBeats) {
      s.pings.push_back(maxPingMs);
    } else {
      s.pings[s.next] = maxPingMs;
      s.next = (s.next + 1) % kWindowBeats;
    }
  }

  float NET_LagCurrentMs()
  {
    if (net_LagAuto == 0) {
      return net_Lag;
    }
    const Clock::time_point now = Clock::now();
    State& s = S();
    std::scoped_lock lock(s.mutex);
    if (s.pings.size() < kMinSamples) {
      return s.started ? s.currentMs : net_Lag;
    }
    if (!s.started) {
      s.started = true;
      s.currentMs = net_Lag;
      s.lastChange = now;
    }
    if (MsBetween(s.lastRecompute, now) < kRecomputeEveryMs) {
      return s.currentMs;
    }
    s.lastRecompute = now;
    const float roundTrip = Percentile99(s.pings);
    const float lo = static_cast<float>(std::max(net_LagMin, 0));
    const float hi = std::max(lo, static_cast<float>(net_LagMax));
    const float target = std::clamp(roundTrip * 0.5f + kMarginMs, lo, hi);
    if (target > s.currentMs) {
      s.currentMs = target;
      s.lastChange = now;
    } else if (target < s.currentMs && MsBetween(s.lastChange, now) >= kDropEveryMs) {
      s.currentMs = std::max(target, s.currentMs - kDropStepMs);
      s.lastChange = now;
    }
    if (s.loggedMs < 0.0f || std::abs(s.currentMs - s.loggedMs) >= 25.0f) {
      gpg::Logf("NET: order delay %.0f ms (99%% of round trips within %.0f ms)", s.currentMs, roundTrip);
      s.loggedMs = s.currentMs;
    }
    return s.currentMs;
  }

  void NET_LagReset()
  {
    State& s = S();
    std::scoped_lock lock(s.mutex);
    s.pings.clear();
    s.next = 0;
    s.started = false;
    s.currentMs = 0.0f;
    s.loggedMs = -1.0f;
  }
} // namespace moho
