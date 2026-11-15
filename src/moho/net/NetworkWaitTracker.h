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
    // A stall: the session had run out of beats (the net_Lag lead was used up) and this
    // peer had not sent the next one. Its length is the time the game stood still.
    std::uint64_t gameWaitEpisodes = 0; // stalls on this peer over the session
    double gameAverageWaitMs = 0;       // their average length
  };

  /**
   * Engine addition (not in the binary): which clients a stalled beat is waiting on.
   *
   * A beat runs once every client has confirmed every other client's commands for it
   * (`CClientBase::IsReadyForBeat`). `lacks[r]` has bit s set when client r has not
   * confirmed client s's beat yet: for the local client that is a beat we have not
   * received, for a remote client a confirmation it has not sent us. A missing
   * confirmation does not say whose fault it is: r may lack s's beat because s sends
   * late, or r's own connection may be slow. Each gap is put on the side with more
   * gaps: a sender most clients lack sends late; a client that lacks most senders
   * (ourselves included, through the beats we have not received) has the slow
   * connection. With as many on both sides, the client with more gaps of either kind
   * is waited on, and both when that ties too: from here the two can't be told apart. A client that has not confirmed
   * its own beat, which it sends together with the beat, is waited on.
   *
   * So one late sender is the only one waited on, not every client still missing its
   * beat, and when the others have not confirmed our beat, the local client is the
   * one waited on: our own connection is the slow one. When we lack the beat of every
   * other client (two or more of them) and none of them has confirmed ours either, the
   * one link they all share is ours, and the local client alone is waited on: a slow
   * download of ours delays every beat and every confirmation we receive alike. Others
   * that sent late but confirmed our beat on time are the ones waited on.
   *
   * `present` holds the clients that take part (not ejected); `count` is at most 64.
   */
  [[nodiscard]] inline std::uint64_t NetworkWaitBlame(
    const std::uint64_t* const lacks,
    const unsigned count,
    const unsigned local,
    const std::uint64_t present
  )
  {
    const auto bit = [](const unsigned i) {
      return std::uint64_t{1} << i;
    };
    unsigned rowGaps[64]{};
    unsigned columnGaps[64]{};
    for (unsigned r = 0; r < count; ++r) {
      for (unsigned s = 0; s < count; ++s) {
        if ((lacks[r] & bit(s)) != 0) {
          ++rowGaps[r];
          ++columnGaps[s];
        }
      }
    }
    std::uint64_t blamed = 0;
    for (unsigned r = 0; r < count; ++r) {
      for (unsigned s = 0; s < count; ++s) {
        if ((lacks[r] & bit(s)) == 0) {
          continue;
        }
        if (r == s) {
          blamed |= bit(r);
          continue;
        }
        unsigned receiverSide = rowGaps[r];
        unsigned senderSide = columnGaps[s];
        if (receiverSide == senderSide) {
          // A tie: the client with more gaps of either kind; both when that ties too.
          receiverSide = rowGaps[r] + columnGaps[r];
          senderSide = rowGaps[s] + columnGaps[s];
        }
        if (receiverSide >= senderSide) {
          blamed |= bit(r);
        }
        if (senderSide >= receiverSide) {
          blamed |= bit(s);
        }
      }
    }
    const std::uint64_t others = present & ~bit(local);
    bool everyConfirmationLate = true;
    for (unsigned r = 0; r < count; ++r) {
      if ((others & bit(r)) != 0 && (lacks[r] & bit(local)) == 0) {
        everyConfirmationLate = false;
      }
    }
    if ((others & (others - 1)) != 0 && (lacks[local] & others) == others && everyConfirmationLate) {
      return bit(local);
    }
    return blamed;
  }

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
      const std::uint64_t waitingOn
    )
    {
      if (!mSpans.empty() && now < mSpans.back().end) {
        // The clock went backwards: a new session; nothing carries over.
        *this = NetworkWaitTracker{};
      }

      const double elapsed = mHaveSample ? (std::max)(0.0, (std::min)(now - mLastTime, kMaxSampleGapSeconds)) : 0.0;
      if (mLastActive) {
        mGameSeconds += elapsed;
        for (unsigned i = 0; i < kMaxPeers; ++i) {
          if (mLastPeers & (std::uint64_t{1} << i)) {
            mPeerGameSeconds[i] += elapsed;
            mStallSeconds[i] += elapsed;
          }
        }
      }

      const std::uint64_t peers = active ? waitingOn : 0;
      // A peer's stall ends when it is no longer waited on; a stall shared with other
      // peers is one stall for each of them, however the others come and go.
      for (unsigned i = 0; i < kMaxPeers; ++i) {
        if (!(peers & (std::uint64_t{1} << i)) && mStallSeconds[i] > 0) {
          ++mEpisodeCounts[i];
          mEpisodeSeconds[i] += mStallSeconds[i];
          mStallSeconds[i] = 0;
        }
      }

      mHaveSample = true;
      mLastTime = now;
      mLastActive = active;
      mLastPeers = peers;

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
          result.gameAverageWaitMs = mEpisodeSeconds[peer] * 1000.0 / static_cast<double>(mEpisodeCounts[peer]);
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
    double mEpisodeSeconds[kMaxPeers]{}; // total length of the counted stalls
    double mStallSeconds[kMaxPeers]{};   // length of the stall in progress

    double mGameSeconds = 0;
    double mPeerGameSeconds[kMaxPeers]{};
    bool mHaveSample = false;
    double mLastTime = 0;
    bool mLastActive = false;
    std::uint64_t mLastPeers = 0;
  };
} // namespace moho
