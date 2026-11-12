#include "remote/client/DisplayModel.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <deque>
#include <limits>
#include <vector>

#include "remote/client/BeatClock.h"

// Engine addition, server mode: see DisplayModel.h.

namespace faf::remote::client
{
  namespace
  {
    // `wld_SkewRateAdjustBase` and `wld_SkewRateAdjustMax`'s defaults (RuntimeTuningGlobals.cpp).
    constexpr double kSkewBase = 1.03;
    constexpr double kSkewMax = 1.15;
    constexpr double kBeatSeconds = 0.1; // speed 0

    struct SQueued
    {
      SBeatStamp stamp;
      double quickest = -1.0; // a real beat's quickest possible arrival; -1 for a made-up one
    };
  } // namespace

  SDisplayRun RunDisplayModel(
    const std::span<const SViewArrival> arrivals,
    const EDisplayPolicy policy,
    const SInterpConfig& config,
    const double frameSeconds
  )
  {
    SDisplayRun run;
    if (arrivals.empty() || !(frameSeconds > 0.0)) {
      return run;
    }
    CInterpBuffer buffer;
    if (policy == EDisplayPolicy::Master) {
      SInterpConfig master;
      master.enabled = true;
      master.adaptive = false;
      master.floorBeats = 1;
      master.synthBeats = 0;
      buffer.Configure(master);
    } else {
      buffer.Configure(config);
    }
    buffer.SetBeatSeconds(kBeatSeconds);
    CBeatClock clock{1}; // the driver before the buffer: `kTargetBacklog` 1

    double quickestTransit = std::numeric_limits<double>::infinity();
    for (const SViewArrival& arrival : arrivals) {
      quickestTransit = std::min(quickestTransit, arrival.localSeconds - arrival.serverSeconds);
    }

    std::deque<SQueued> queue;
    std::vector<double> delays;
    std::size_t next = 0;
    double now = arrivals.front().localSeconds;
    const double end = arrivals.back().localSeconds; // after it the views simply ended: no stall to count
    bool started = false;
    std::int32_t gameTick = 0;
    bool lastBeatWasTick = true;
    double timeSinceLastTick = 0.0;
    bool stalling = false;
    double stallStart = 0.0;
    double targetSum = 0.0;

    const auto take = [&](const SQueued& queued) {
      gameTick = queued.stamp.tick;
      lastBeatWasTick = queued.stamp.advanced;
      buffer.OnTaken(queued.stamp, now);
      clock.OnShown(static_cast<std::uint32_t>(queued.stamp.beat));
      switch (queued.stamp.kind) {
      case EBeatKind::Real:
        delays.push_back(now - queued.quickest);
        break;
      case EBeatKind::CatchUp:
        ++run.catchUps;
        break;
      case EBeatKind::Synthesized:
        ++run.synthesized;
        break;
      }
      run.ticksShown += queued.stamp.advanced ? 1u : 0u;
    };

    while (now <= end) {
      while (next < arrivals.size() && arrivals[next].localSeconds <= now) {
        const SViewArrival& arrival = arrivals[next++];
        SQueued queued;
        queued.stamp = buffer.OnView(arrival.beat, arrival.serverSeconds, arrival.localSeconds);
        queued.quickest = arrival.serverSeconds + quickestTransit;
        clock.OnFrame(
          static_cast<std::uint32_t>(arrival.beat),
          0,
          static_cast<std::uint32_t>(std::llround(arrival.serverSeconds * 1000.0)),
          arrival.localSeconds
        );
        queue.push_back(queued);
      }
      ++run.frames;
      if (!started) {
        // `WLD_DoInitializing`: the first beat, as soon as there is one.
        if (!queue.empty() && (policy == EDisplayPolicy::Master || !buffer.HoldStart())) {
          take(queue.front());
          queue.pop_front();
          started = true;
          timeSinceLastTick = 0.0;
        }
        now += frameSeconds;
        continue;
      }

      // `CWldSession::SessionFrame` and `WLD_GetSimRate`.
      const double speed =
        policy == EDisplayPolicy::Master ? (clock.HasFrames() ? clock.Skew() : 0.0) : buffer.Skew(now);
      const double rate = std::clamp(std::pow(kSkewBase, -speed), 1.0 / kSkewMax, kSkewMax);
      if (!lastBeatWasTick) {
        timeSinceLastTick = 1.0;
      } else {
        timeSinceLastTick += rate * frameSeconds / kBeatSeconds;
      }
      const std::int32_t tickAtFrameStart = gameTick;
      const std::int32_t targetTick = gameTick + static_cast<std::int32_t>(std::floor(timeSinceLastTick));
      bool wanted = false;
      std::uint64_t advanced = 0;
      std::uint64_t real = 0;
      for (int applied = 0; applied < 100; ++applied) {
        if (gameTick >= targetTick) {
          break;
        }
        if (queue.empty()) {
          // `HasSyncData` with nothing held: the driver may make one up.
          if (const std::optional<SBeatStamp> made = buffer.OnUnderrun(now); made) {
            queue.push_back(SQueued{*made, -1.0});
          } else {
            wanted = true;
            break;
          }
        }
        const SQueued queued = queue.front();
        queue.pop_front();
        take(queued);
        advanced += queued.stamp.advanced ? 1u : 0u;
        real += queued.stamp.kind != EBeatKind::Synthesized ? 1u : 0u;
      }
      const double remainder = timeSinceLastTick - static_cast<double>(gameTick - tickAtFrameStart);
      timeSinceLastTick = std::clamp(remainder, 0.0, 1.0);

      if (wanted) {
        ++run.stallFrames;
        if (!stalling) {
          stalling = true;
          stallStart = now;
          ++run.stallEvents;
        }
      } else if (stalling && advanced != 0u) {
        stalling = false;
        run.stallSeconds += now - stallStart;
        run.longestStall = std::max(run.longestStall, now - stallStart);
      }
      if (advanced >= 2u) {
        ++run.jumpFrames;
        run.jumpBeats += advanced - 1u;
      }
      run.mergedFrames += real >= 2u ? 1u : 0u;
      const std::int32_t target = policy == EDisplayPolicy::Master ? 1 : buffer.TargetDepth();
      targetSum += static_cast<double>(target);
      run.mostTarget = std::max(run.mostTarget, target);
      now += frameSeconds;
    }
    if (stalling) {
      run.stallSeconds += now - stallStart;
      run.longestStall = std::max(run.longestStall, now - stallStart);
    }
    run.meanTarget = run.frames != 0u ? targetSum / static_cast<double>(run.frames) : 0.0;
    if (!delays.empty()) {
      double sum = 0.0;
      for (const double delay : delays) {
        sum += delay;
      }
      run.meanDelayMs = sum / static_cast<double>(delays.size()) * 1000.0;
      std::sort(delays.begin(), delays.end());
      run.p95DelayMs =
        delays[std::min(delays.size() - 1u, static_cast<std::size_t>(0.95 * static_cast<double>(delays.size())))] *
        1000.0;
    }
    run.buffer = buffer.Stats();
    return run;
  }

  std::string DescribeDisplayRun(
    const char* const label,
    const SDisplayRun& run
  )
  {
    char text[640];
    std::snprintf(
      text,
      sizeof(text),
      "%s: %llu frames, %llu ticks shown; stalls %llu frames in %llu runs (%.2f s, longest %.2f s); jumps %llu frames "
      "(%llu ticks unshown), %llu frames with two real beats; made up %llu, catch-up %llu, views late %llu; display "
      "behind the quickest view %.0f ms mean, %.0f ms p95; depth target %.2f mean, %d most",
      label,
      static_cast<unsigned long long>(run.frames),
      static_cast<unsigned long long>(run.ticksShown),
      static_cast<unsigned long long>(run.stallFrames),
      static_cast<unsigned long long>(run.stallEvents),
      run.stallSeconds,
      run.longestStall,
      static_cast<unsigned long long>(run.jumpFrames),
      static_cast<unsigned long long>(run.jumpBeats),
      static_cast<unsigned long long>(run.mergedFrames),
      static_cast<unsigned long long>(run.synthesized),
      static_cast<unsigned long long>(run.catchUps),
      static_cast<unsigned long long>(run.buffer.lateViews),
      run.meanDelayMs,
      run.p95DelayMs,
      run.meanTarget,
      static_cast<int>(run.mostTarget)
    );
    return text;
  }
} // namespace faf::remote::client
