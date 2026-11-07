#pragma once

// Engine addition, dedicated server: decides which sim speed news deserves a console line. A speed
// that flickers between two steps says nothing, so a new speed counts only once it has held; a slow
// sim warns once, and calls the danger over only once it has clearly passed.

#include <algorithm>
#include <cmath>

namespace faf::server
{
  /** A beat at speed +0. A beat that takes longer is speed -1 (`RATE_GameRateToSpeed` rounds down). */
  inline constexpr float kSpeedZeroBeatMs = 100.0f;

  inline constexpr double kSpeedHoldSeconds = 15.0;
  inline constexpr double kSlowHoldSeconds = 5.0;
  inline constexpr double kCalmHoldSeconds = 30.0;
  inline constexpr float kCalmShare = 0.85f;

  /** `WLD_GetSimRate`'s scale: speed +0 is ten beats a second, and ten steps are ten times that. */
  [[nodiscard]] inline double SecondsPerBeat(const int speed)
  {
    return 0.1 / std::pow(10.0, speed * 0.1);
  }

  /** The nearest speed step to a rate of beats, within what the game-speed controls allow. */
  [[nodiscard]] inline int SpeedOfBeatRate(const double beatsPerSecond)
  {
    constexpr int kMinSpeed = -10;
    constexpr int kMaxSpeed = 50;
    if (beatsPerSecond <= 0.0) {
      return kMinSpeed;
    }
    return std::clamp(static_cast<int>(std::lround(10.0 * std::log10(beatsPerSecond * 0.1))), kMinSpeed, kMaxSpeed);
  }

  struct SSpeedSample
  {
    double seconds = 0.0;
    int requested = 0;
    int speed = 0;
    float beatMs = 0.0f; // 0: not measured yet
  };

  struct SSpeedNews
  {
    bool requestChanged = false;
    int requestedBefore = 0;
    bool speedChanged = false;
    int speedBefore = 0;
    bool slowStarted = false;
    bool slowEnded = false;
  };

  class CSpeedWatch
  {
  public:
    /** Warns when a beat takes `warnBeatMs` or more. */
    explicit CSpeedWatch(const float warnBeatMs)
      : mWarnBeatMs(warnBeatMs)
    {}

    [[nodiscard]] SSpeedNews Update(const SSpeedSample& sample)
    {
      SSpeedNews news;
      if (!mStarted) {
        mStarted = true;
        mRequested = sample.requested;
        mSpeed = sample.speed;
        mCandidate = sample.speed;
      }

      if (sample.requested != mRequested) {
        news.requestChanged = true;
        news.requestedBefore = mRequested;
        mRequested = sample.requested;
      }

      if (sample.speed != mCandidate) {
        mCandidate = sample.speed;
        mCandidateSince = sample.seconds;
      } else if (mCandidate != mSpeed && sample.seconds - mCandidateSince >= kSpeedHoldSeconds) {
        news.speedChanged = true;
        news.speedBefore = mSpeed;
        mSpeed = mCandidate;
      }

      if (sample.beatMs > 0.0f) {
        const bool over = sample.beatMs >= mWarnBeatMs;
        const bool calm = sample.beatMs < mWarnBeatMs * kCalmShare;
        if (mSlow ? !calm : !over) {
          mHoldSince = -1.0;
        } else if (mHoldSince < 0.0) {
          mHoldSince = sample.seconds;
        }
        if (mHoldSince >= 0.0 && sample.seconds - mHoldSince >= (mSlow ? kCalmHoldSeconds : kSlowHoldSeconds)) {
          news.slowStarted = !mSlow;
          news.slowEnded = mSlow;
          mSlow = !mSlow;
          mHoldSince = -1.0;
        }
      }
      return news;
    }

  private:
    float mWarnBeatMs;
    bool mStarted = false;
    int mRequested = 0;
    int mSpeed = 0;
    int mCandidate = 0;
    double mCandidateSince = 0.0;
    bool mSlow = false;
    double mHoldSince = -1.0;
  };
} // namespace faf::server
