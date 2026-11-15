#pragma once

#include <algorithm>
#include <cstdint>
#include <deque>

namespace moho
{
  /**
   * Engine addition (not in the binary): how long this client waited on one peer.
   * The window values cover the last 30 s of real time; the game values cover the
   * whole session.
   */
  struct NetworkWaitMetrics
  {
    double observedSeconds = 0; // active (unpaused, demanded) time in the window
    double waitingMs = 0;       // time in the window spent waiting on this peer
    double longestMs = 0;       // longest unbroken wait on this peer in the window
    double gameSeconds = 0;     // active time over the whole session
    double gameWaitPercent = 0; // share of gameSeconds spent waiting on this peer
    std::uint64_t gameWaitEpisodes = 0;
    double gameAverageWaitMs = 0;
  };

  /**
   * Engine addition (not in the binary): records, from wall-clock samples, when
   * the session was running and which peers (bit i = client index i, up to 64) it
   * was waiting on. It only reads what it is given; nothing it holds reaches the
   * sim or the network. Waits shared by several peers count for each of them, and
   * time while paused or not demanding a beat counts for nobody.
   */
  class NetworkWaitTracker
  {
  public:
    static constexpr unsigned kMaxPeers = 64;
    static constexpr double kWindowSeconds = 30.0;
    // A gap between samples longer than this (a hitch, a debugger) adds at most this much.
    static constexpr double kMaxSampleGapSeconds = 5.0;

    void Observe(
      const double now,
      const bool active,
      const std::uint64_t peers
    )
    {
      if (!mSpans.empty() && now < mSpans.back().end) {
        // The clock went backwards: a new session; nothing carries over.
        *this = NetworkWaitTracker{};
      }

      if (mHaveSample && mLastActive) {
        const double seconds = (std::max)(0.0, (std::min)(now - mLastTime, kMaxSampleGapSeconds));
        mGameSeconds += seconds;
        for (unsigned i = 0; i < kMaxPeers; ++i) {
          if (mLastPeers & (std::uint64_t{1} << i)) {
            mPeerGameSeconds[i] += seconds;
          }
        }
      }
      mHaveSample = true;
      mLastTime = now;
      mLastActive = active;
      mLastPeers = active ? peers : 0;

      // An episode counts once it has accumulated waiting time. Another peer
      // joining or leaving a shared stall does not split this peer's episode.
      if (!mSpans.empty() && mSpans.back().active && now > mSpans.back().end) {
        const std::uint64_t newlyCounted = mSpans.back().peers & ~mCountedEpisodes;
        for (unsigned i = 0; i < kMaxPeers; ++i) {
          if (newlyCounted & (std::uint64_t{1} << i)) {
            ++mEpisodeCounts[i];
          }
        }
        mCountedEpisodes |= mSpans.back().peers;
      }
      mCountedEpisodes &= active ? peers : 0;

      if (!mSpans.empty()) {
        mSpans.back().end = now;
      }
      if (mSpans.empty() || mSpans.back().active != active || mSpans.back().peers != peers) {
        mSpans.push_back({now, now, active, peers});
      }
      while (mSpans.size() > 1 && mSpans.front().end <= now - kWindowSeconds) {
        mSpans.pop_front();
      }
    }

    [[nodiscard]] NetworkWaitMetrics Read(
      const double now,
      const unsigned peer
    ) const
    {
      NetworkWaitMetrics result;
      double run = 0;
      for (const Span& span : mSpans) {
        const double end = &span == &mSpans.back() ? now : span.end;
        const double seconds = (std::max)(0.0, end - (std::max)(span.begin, now - kWindowSeconds));
        if (span.active) {
          result.observedSeconds += seconds;
        }
        if (span.active && peer < kMaxPeers && (span.peers & (std::uint64_t{1} << peer))) {
          result.waitingMs += seconds * 1000.0;
          run += seconds * 1000.0;
          result.longestMs = (std::max)(result.longestMs, run);
        } else if (seconds > 0) {
          run = 0;
        }
      }

      result.gameSeconds = mGameSeconds;
      if (peer < kMaxPeers) {
        result.gameWaitEpisodes = mEpisodeCounts[peer];
        if (mGameSeconds > 0) {
          result.gameWaitPercent = mPeerGameSeconds[peer] * 100.0 / mGameSeconds;
        }
        if (mEpisodeCounts[peer] > 0) {
          result.gameAverageWaitMs = mPeerGameSeconds[peer] * 1000.0 / static_cast<double>(mEpisodeCounts[peer]);
        }
      }
      return result;
    }

  private:
    struct Span
    {
      double begin;
      double end;
      bool active;
      std::uint64_t peers;
    };

    std::deque<Span> mSpans;
    std::uint64_t mEpisodeCounts[kMaxPeers]{};
    std::uint64_t mCountedEpisodes = 0;

    double mGameSeconds = 0;
    double mPeerGameSeconds[kMaxPeers]{};
    bool mHaveSample = false;
    double mLastTime = 0;
    bool mLastActive = false;
    std::uint64_t mLastPeers = 0;
  };
} // namespace moho
