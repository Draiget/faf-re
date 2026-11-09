#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <algorithm>
#include <cstdint>
#include <mutex>

// Engine addition (plan WP10.10), not in the binary: the bytes a server-mode client receives in each lane of the
// server's views, for the network panel (#322) and the driver's log summary. The network driver records each view
// as it takes it (its thread); the panel reads a snapshot (the render thread). Header only: the panel's library
// needs no link to the client's.

namespace faf::remote::client
{
  enum class EServerLane : std::uint8_t
  {
    Entities, // own and team frames
    Armies,
    Grids,
    Lua,
    Poses,
    Count,
  };

  inline constexpr std::size_t kServerLaneCount = static_cast<std::size_t>(EServerLane::Count);

  [[nodiscard]] constexpr const char* ServerLaneName(const EServerLane lane) noexcept
  {
    switch (lane) {
    case EServerLane::Entities:
      return "entities";
    case EServerLane::Armies:
      return "armies";
    case EServerLane::Grids:
      return "grids";
    case EServerLane::Lua:
      return "Lua";
    case EServerLane::Poses:
      return "poses";
    case EServerLane::Count:
      break;
    }
    return "?";
  }

  struct SServerLaneSnapshot
  {
    bool active = false;                                // a server-mode game has taken a view
    std::uint64_t views = 0;
    std::array<std::uint64_t, kServerLaneCount> total{}; // bytes since the game started
    std::array<double, kServerLaneCount> perSecond{};    // bytes a second over the last whole seconds (up to 5)
    double seconds = 0.0;                                // how many seconds `perSecond` covers
  };

  class CServerLaneMeter
  {
  public:
    using Clock = std::chrono::steady_clock;
    static constexpr int kWindowSeconds = 5;

    /** The process's meter. */
    [[nodiscard]] static CServerLaneMeter& Get()
    {
      static CServerLaneMeter meter;
      return meter;
    }

    /** A new game: everything from zero. */
    void Reset()
    {
      const std::lock_guard lock(mMutex);
      mActive = false;
      mViews = 0;
      mTotal = {};
      mBuckets = {};
      mFirstSecond = 0;
      mLastSecond = -1;
    }

    /** One view's bytes by lane, as taken at `now`. */
    void Record(const std::array<std::uint64_t, kServerLaneCount>& bytes, const Clock::time_point now = Clock::now())
    {
      const std::lock_guard lock(mMutex);
      const auto second = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
      if (!mActive) {
        mActive = true;
        mFirstSecond = second;
      }
      Roll(second);
      ++mViews;
      for (std::size_t lane = 0; lane < kServerLaneCount; ++lane) {
        mTotal[lane] += bytes[lane];
        mBuckets[static_cast<std::size_t>(second % (kWindowSeconds + 1))][lane] += bytes[lane];
      }
    }

    /** The totals, and the rate over the last whole seconds (the one under way left out). */
    [[nodiscard]] SServerLaneSnapshot Snapshot(const Clock::time_point now = Clock::now())
    {
      const std::lock_guard lock(mMutex);
      SServerLaneSnapshot out;
      out.active = mActive;
      out.views = mViews;
      out.total = mTotal;
      if (!mActive) {
        return out;
      }
      const auto second = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
      Roll(second);
      const auto whole = std::min<std::int64_t>(kWindowSeconds, second - mFirstSecond);
      for (std::int64_t back = 1; back <= whole; ++back) {
        const auto& bucket = mBuckets[static_cast<std::size_t>((second - back) % (kWindowSeconds + 1))];
        for (std::size_t lane = 0; lane < kServerLaneCount; ++lane) {
          out.perSecond[lane] += static_cast<double>(bucket[lane]);
        }
      }
      out.seconds = static_cast<double>(whole);
      if (whole > 0) {
        for (double& rate : out.perSecond) {
          rate /= static_cast<double>(whole);
        }
      }
      return out;
    }

  private:
    CServerLaneMeter() = default;
    CServerLaneMeter(const CServerLaneMeter&) = delete;
    CServerLaneMeter& operator=(const CServerLaneMeter&) = delete;

    /** Empties the buckets of the seconds since the last one seen (a bucket is reused every kWindowSeconds + 1). */
    void Roll(const std::int64_t second)
    {
      if (second <= mLastSecond) {
        return;
      }
      const std::int64_t from = std::max(mLastSecond + 1, second - kWindowSeconds);
      for (std::int64_t s = from; s <= second; ++s) {
        mBuckets[static_cast<std::size_t>(s % (kWindowSeconds + 1))] = {};
      }
      mLastSecond = second;
    }

    std::mutex mMutex;
    bool mActive = false;
    std::uint64_t mViews = 0;
    std::array<std::uint64_t, kServerLaneCount> mTotal{};
    std::array<std::array<std::uint64_t, kServerLaneCount>, kWindowSeconds + 1> mBuckets{};
    std::int64_t mFirstSecond = 0;
    std::int64_t mLastSecond = -1;
  };
} // namespace faf::remote::client
