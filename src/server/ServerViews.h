#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "remote/ViewLanes.h"

namespace moho
{
  class RRuleGameRules;
}

// Engine addition, dedicated server (plan WP5, WP10.4): each player's view of the game, every beat,
// on its way to them. Views are built only for armies with a player, with ids of their own, on threads
// of their own so the sim goes on to its next beat meanwhile.
//
// A frame is encoded against the one before it, so the player must have received that one: they go on
// the reliable stream. A lost datagram then costs a resend's wait, never a wrong picture. Sending frames
// unreliably against the newest acknowledged one would cost no wait, and needs the held frames to encode
// against an older frame, which they don't do.
//
// A player back from a lost connection holds none of that, so their next view is whole: its frames carry
// every record they'd hold, against nothing, and its army and grid lanes are whole too (plan WP14.1). The
// Lua lane can't be: what the UI built from earlier beats' `Sync` needs the client's resync (WP6.8).

namespace faf::server
{
  class CServerNet;

  /** The `GameInfo` message for a player (remote/net/GameLinks.h). */
  [[nodiscard]] std::vector<std::uint8_t> MakeGameInfo(float mapSizeX, float mapSizeZ, std::int32_t army, std::uint32_t source);

  /**
   * Plan WP15.4 (#200): the pauses each player has been granted, by command source: the match's `Timeouts`, plus what the
   * organiser added; -1 is unlimited. Only the main thread writes it and the numbers only grow, so the views, which count
   * the pauses they see on the sim thread, show `granted - seen` whatever the two threads' order (the main thread spends
   * its own count when it sees a pause, which may be before or after the views read this).
   */
  class CPauseBook
  {
  public:
    void SetGranted(const std::uint32_t source, const int granted)
    {
      const std::scoped_lock lock(mLock);
      mGranted[source] = granted;
    }
    [[nodiscard]] std::optional<int> Granted(const std::uint32_t source) const
    {
      const std::scoped_lock lock(mLock);
      const auto found = mGranted.find(source);
      return found == mGranted.end() ? std::nullopt : std::optional<int>(found->second);
    }

  private:
    mutable std::mutex mLock;
    std::map<std::uint32_t, int> mGranted;
  };

  class CServerViews final : public remote::CViewLanes
  {
  public:
    /** `players`: army to uid. `teams`: one view per team and each player's own units (remote/ViewPackets.h). */
    CServerViews(
      const remote::wire::SContentTables& tables, moho::RRuleGameRules& rules, float mapSizeX, float mapSizeZ, CServerNet& net,
      std::map<std::size_t, std::int32_t> players, unsigned int threads, bool teams
    );
    ~CServerViews() override;

    void Install();
    /**
     * Plan WP13.6, before `Install`, with team views: a player whose command source leaves every army (defeated, the whole
     * team out, observers allowed) watches everything from then on, as the original client's `SetFocusArmy(-1)` does.
     */
    void EnableObserverViews()
    {
      mObserverViews = true;
      EnableObserverView();
    }
    /** Call with the sim stopped. */
    void Uninstall();

    [[nodiscard]] std::uint64_t Failures() const noexcept { return mFailures; }
    /** #178: the game speed the frames carry (the requested sim rate), from any thread. */
    void SetFrameSimRate(const int rate) noexcept { mFrameSimRate.store(rate, std::memory_order_relaxed); }
    /** Plan WP15.4: the pause counts to show the players; before `Install`. */
    void SetPauseBook(std::shared_ptr<const CPauseBook> book) { mPauseBook = std::move(book); }
    /** What the views have been made of so far, for the console. */
    [[nodiscard]] std::string LaneReport() const;

  protected:
    /** Last beat's views are over, so the id maps are quiet: the players' commands go in, and whoever left loses their view. */
    void OnBeatStarting() override;
    void OnLanesEncoded(std::size_t army, const SLanes& lanes) override;
    /** Plan WP11: each beat's Lua lane goes as its own `LuaSync` message once `Sim::Sync` has routed the beat's table. */
    void OnLuaRouterMade(remote::CSyncRouter& router) override;
    /** Plan WP11 step 4: the beat's new session-table entries go to every player before the beat's views. */
    void OnViewFrames(moho::Sim& sim) override;
    void OnViewsFinished() override;

  private:
    std::shared_ptr<const CPauseBook> mPauseBook;
    std::int32_t mPausedSeen = -1;              // on the sim thread: the source the game was paused by last beat
    std::map<std::uint32_t, int> mPausesSeen;   // likewise: the pauses each source took (each one the server let through)
    std::optional<int> mPauseShown;             // the pauses left the pausing player is shown during this pause
    moho::RRuleGameRules& mRules;
    CServerNet& mNet;
    std::map<std::size_t, std::int32_t> mPlayers;
    std::uint32_t mViewMask = 0u;
    std::uint64_t mFailures = 0;
    std::atomic<std::uint64_t> mFrameBytes{0};
    std::atomic<std::uint64_t> mArmyBytes{0};
    std::atomic<std::uint64_t> mGridBytes{0};
    std::atomic<std::uint64_t> mLuaBytes{0};
    std::atomic<std::uint64_t> mPoseBytes{0};
    std::atomic<int> mFrameSimRate{0};
    std::chrono::steady_clock::time_point mStart = std::chrono::steady_clock::now();
    std::atomic<std::uint64_t> mTableBytes{0}; // one player's share
    std::atomic<std::uint64_t> mTableRecords{0};
    remote::wire::CSessionTableWriters mSessionTables; // one for every view (`EnableSessionTables`)
    bool mInstalled = false;
    bool mObserverViews = false;
  };
} // namespace faf::server
