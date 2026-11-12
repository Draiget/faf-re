#include "remote/client/InterpBuffer.h"

#include <algorithm>
#include <cmath>
#include <vector>

// Engine addition, server mode: see InterpBuffer.h.

namespace faf::remote::client
{
  void CInterpBuffer::Configure(
    const SInterpConfig& config
  ) noexcept
  {
    mConfig = config;
    mConfig.floorBeats = std::max<std::int32_t>(mConfig.floorBeats, 0);
    mConfig.maxBeats = std::max(mConfig.maxBeats, mConfig.floorBeats);
    mConfig.synthBeats = std::max<std::int32_t>(mConfig.synthBeats, 0);
    if (!mConfig.enabled) {
      mTarget = 0;
    } else if (!mConfig.adaptive) {
      mTarget = mConfig.floorBeats;
    } else {
      mTarget = std::clamp(mTarget, mConfig.floorBeats, mConfig.maxBeats);
    }
    mStats.mostTarget = std::max(mStats.mostTarget, mTarget);
  }

  void CInterpBuffer::SetBeatSeconds(
    const double seconds
  ) noexcept
  {
    if (seconds > 0.0) {
      mBeatSeconds = seconds;
    }
  }

  SBeatStamp CInterpBuffer::OnView(
    const std::int32_t beat,
    const double serverSeconds,
    const double now
  )
  {
    ++mStats.views;
    if (beat <= mWantedTick) {
      ++mStats.lateViews; // the display asked for this tick before it came
    }
    SBeatStamp stamp;
    stamp.beat = beat;
    if (beat <= mSynthUntil) {
      // A made-up beat took this display tick: the real one is applied at the tick already shown, with no time of its
      // own, and the next beat that gets display time starts from what the screen showed.
      stamp.kind = EBeatKind::CatchUp;
      stamp.tick = std::max(mLastTick, 0);
      stamp.advanced = false;
      ++mStats.catchUps;
    } else {
      stamp.kind = EBeatKind::Real;
      stamp.tick = std::max(beat, mLastTick + 1);
      stamp.advanced = true;
    }
    mLastTick = stamp.tick;
    mFirstBeat = mFirstBeat < 0 ? beat : mFirstBeat;
    mLastRealBeat = std::max(mLastRealBeat, beat);

    // An outage (no view at all for longer than `kOutageSeconds`: a cut, the server's own pause in sending) isn't
    // jitter: no depth would have covered it, so neither its first view nor those that come in the burst behind it size
    // it. The burst lasts while views come faster than half a beat apart (the held-back views, as fast as the link
    // delivers them); the first view after a normal gap is a sample again.
    const double gap = now - mLastViewAt;
    if (mStats.views > 1u && gap > kOutageSeconds) {
      ++mStats.outages;
      mInOutageBurst = true;
    } else if (mInOutageBurst && gap >= kBurstGapBeats * mBeatSeconds) {
      mInOutageBurst = false;
    }
    mLastViewAt = now;
    if (!mInOutageBurst) {
      mTransits.push_back(now - serverSeconds);
      while (mTransits.size() > kWindow) {
        mTransits.pop_front();
      }
    }
    Resize(now);
    return stamp;
  }

  void CInterpBuffer::Resize(
    const double now
  )
  {
    // The views' lateness: each one's transit (arrival minus the server's stamp) against the quickest of the window,
    // so neither clock's start matters. Lost datagrams show here too: a view behind one waits for its resend.
    if (mTransits.size() >= 2u) {
      std::vector<double> lateness(mTransits.begin(), mTransits.end());
      const double quickest = *std::min_element(lateness.begin(), lateness.end());
      for (double& value : lateness) {
        value -= quickest;
      }
      std::sort(lateness.begin(), lateness.end());
      const std::size_t n = lateness.size();
      const double median = lateness[n / 2u];
      const std::size_t at95 =
        std::min(n - 1u, static_cast<std::size_t>(std::ceil(0.95 * static_cast<double>(n))) - 1u);
      const double p95 = lateness[at95];
      mStats.latenessMedianMs = median * 1000.0;
      mStats.lateness95Ms = p95 * 1000.0;

      if (mConfig.enabled && mConfig.adaptive && n >= kWarmup) {
        // One beat, and the margin by which the slowest views (the 95th percentile) come later than the usual ones,
        // with a little slack: the plan's "1 tick plus a jitter margin measured from arrival times", the floor below
        // it.
        const double margin = (p95 - median) / mBeatSeconds;
        std::int32_t need = std::max<std::int32_t>(1, static_cast<std::int32_t>(std::ceil(margin + kSlackBeats)));
        need = std::clamp(need, mConfig.floorBeats, mConfig.maxBeats);
        if (need > mTarget) {
          mTarget = need; // at once: a late view would stall the picture
          ++mStats.raised;
          mShorterSince = -1.0;
        } else if (need < mTarget) {
          // Slowly: each beat less is a beat of display time taken back, and the views' lateness comes in bursts.
          if (mShorterSince < 0.0) {
            mShorterSince = now;
          } else if (now - mShorterSince >= kShrinkSeconds) {
            --mTarget;
            ++mStats.lowered;
            mShorterSince = now;
          }
        } else {
          mShorterSince = -1.0;
        }
      }
    }
    if (!mConfig.enabled) {
      mTarget = 0;
    } else if (!mConfig.adaptive) {
      mTarget = mConfig.floorBeats;
    } else {
      mTarget = std::clamp(mTarget, mConfig.floorBeats, mConfig.maxBeats);
    }
    mStats.mostTarget = std::max(mStats.mostTarget, mTarget);
  }

  std::optional<SBeatStamp> CInterpBuffer::OnUnderrun(
    const double now
  )
  {
    if (mLastRealBeat < 0) {
      return std::nullopt; // nothing shown yet: the session isn't playing
    }
    const std::int32_t wanted = mLastTick + 1;
    const bool newTick = wanted > mWantedTick;
    if (newTick) {
      mWantedTick = wanted;
      ++mStats.underruns;
    }
    const std::int32_t ahead = wanted - mLastRealBeat;
    if (mConfig.enabled && ahead >= 1 && ahead <= mConfig.synthBeats) {
      SBeatStamp stamp;
      stamp.kind = EBeatKind::Synthesized;
      stamp.beat = mLastRealBeat;
      stamp.tick = wanted;
      stamp.advanced = true;
      stamp.ahead = ahead;
      mLastTick = wanted;
      mSynthUntil = wanted;
      ++mStats.synthesized;
      return stamp;
    }
    if (newTick) {
      ++mStats.stalls;
    }
    if (!mStalled) {
      mStalled = true;
      mStallStart = now;
    }
    return std::nullopt;
  }

  void CInterpBuffer::OnTaken(
    const SBeatStamp& stamp,
    const double now
  ) noexcept
  {
    if (!stamp.advanced) {
      return; // a catch-up beat: the display stays where it was
    }
    mShownTick = stamp.tick;
    mShownAt = now;
    if (mStalled) {
      mStalled = false;
      const double stalled = now - mStallStart;
      mStats.stallSeconds += stalled;
      mStats.longestStall = std::max(mStats.longestStall, stalled);
    }
  }

  double CInterpBuffer::Depth(
    const double now
  ) const noexcept
  {
    if (mLastRealBeat < 0 || mShownTick < 0) {
      return static_cast<double>(mTarget);
    }
    // Both ends move on between their steps: the newest view as the next is due, the display through its tick. Each
    // goes at most one beat past its last step (a late view; a display waiting at the end of its tick).
    const double sinceView = std::clamp((now - mLastViewAt) / mBeatSeconds, 0.0, 1.0);
    const double sinceShown = std::clamp((now - mShownAt) / mBeatSeconds, 0.0, 1.0);
    return (static_cast<double>(mLastRealBeat) + sinceView) - (static_cast<double>(mShownTick) + sinceShown);
  }

  double CInterpBuffer::Skew(
    const double now
  ) const noexcept
  {
    if (mLastRealBeat < 0 || mShownTick < 0) {
      return 0.0;
    }
    const double off = static_cast<double>(mTarget) - Depth(now);
    return std::clamp(off * kSkewPerBeat, -kMaxSkew, kMaxSkew);
  }

  std::int32_t CInterpBuffer::TargetDepth() const noexcept
  {
    return mTarget;
  }
} // namespace faf::remote::client
