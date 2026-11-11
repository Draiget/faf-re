#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "remote/SyncRouting.h"
#include "remote/ViewFrames.h"
#include "remote/wire/ArmyLane.h"
#include "remote/wire/BitStream.h"
#include "remote/wire/LuaSyncLane.h"

// Engine addition, server mode (plan WP5.2, WP16.5, WPR.35): every beat, what a dedicated server
// sends each view's client. The entity frame (remote/ViewFrames.h), the army lane and the grid lane
// (the vision and water grids of the view's army and of every army that counts it as an ally) are
// encoded against what that client received the beat before, and the Lua lane is that view's routed
// `Sync` (remote/SyncRouting.h) when routing is on. Each grid's delta is encoded once for all its
// receivers.
//
// That "received the beat before" holds on a stream that loses nothing. What to do with the bytes is
// the subclass's: a game server sends them (server/ServerViews.h), `--view-bench` counts them.

namespace moho
{
  class CIntelGrid;
}

namespace faf::remote
{
  /** The codec a server's frames use: positions over the map, no dead reckoning. */
  [[nodiscard]] wire::SFrameCodec MakeViewCodec(float mapSizeX, float mapSizeZ);

  class CViewLanes : public CViewFrames
  {
  public:
    CViewLanes(const wire::SContentTables& tables, float mapSizeX, float mapSizeZ);

    /** The Lua lane too, each player's `Sync` as `remote/SyncRouting.h` routes it. */
    void EnableLuaRouting(std::string dumpPrefix)
    {
      mLuaRouting = true;
      mLuaRoutingDump = std::move(dumpPrefix);
    }
    /**
     * With Lua routing: a subclass sends each beat's Lua `Sync` itself once the beat's table is routed (a server's
     * `LuaSync`), so the views' Lua lanes, which would carry the beat before's, stay empty and are not encoded.
     */
    void SendLuaSeparately() noexcept { mLuaSeparately = true; }

  protected:
    /** One view's beat. `ok`: every lane encoded. */
    struct SLanes
    {
      const wire::BitWriter& frame;
      const wire::BitWriter& armies;
      const wire::BitWriter& grids;
      const wire::BitWriter& lua;
      bool ok;
      const wire::BitWriter* team = nullptr; // the player's team's frame, with teams and not cut from it
      const wire::BitWriter* poses = nullptr; // with `EnablePoses`: the units' bones (wire/PoseLane.h)
      std::size_t teamEntities = 0;
      bool fresh = false; // `RequestFresh`: every lane but Lua's is whole, for a client that holds nothing
      // Plan WPR.30, every `kCheckEveryBeats`: what the client should hold after this beat, by `CViewFrames::HeldFrameHash`.
      bool check = false;
      std::uint64_t frameHash = 0;
      std::uint64_t teamHash = 0; // with `team`
    };

    /** How often a client's frames are checked: the most a damaged one goes unnoticed (WPR.31: under a second). */
    static constexpr std::uint32_t kCheckEveryBeats = 8;

    /**
     * Plan WP14.1, on the sim thread between beats: `army`'s client holds nothing any more (it reconnected),
     * so its next beat's frames, army lane and grids go whole. Its Lua lane can't: that needs the client's resync (WP6.8).
     */
    void RequestFresh(std::size_t army)
    {
      if (army < mClients.size()) {
        mClients[army].fresh = true;
      }
    }

    void OnViewFrames(moho::Sim& sim) override;
    /** The grids, encoded in the frames' batch of jobs. */
    std::size_t PrepareSideJobs(moho::Sim& sim) override;
    void RunSideJob(std::size_t index) override;
    void OnViewReady(std::size_t army) override { Send(army); }
    /** Plan WP13.6: a player now watching everything gets their frames whole (with the observer view as their team's). */
    void OnWatchingEverything(std::size_t army) override { RequestFresh(army); }

    /** A view's lanes are encoded. Without a pipeline on a sim worker or the sim thread, with one on its threads. */
    virtual void OnLanesEncoded(std::size_t army, const SLanes& lanes)
    {
      (void)army;
      (void)lanes;
    }
    /** The router exists, before it's installed. */
    virtual void OnLuaRouterMade(CSyncRouter& router) { (void)router; }
    /** The router, ahead of this beat's Lua lanes. */
    virtual void OnLuaRouterBeat(moho::Sim& sim, CSyncRouter& router)
    {
      (void)sim;
      (void)router;
    }

  public:
    /**
     * Plan WP8.2: each view's pose lane within this many bytes a beat (research/WP8.2-pose-budget.md); 0, the
     * default, sends every changed bone as before.
     */
    void SetPoseBudget(const std::size_t bytesPerBeat) noexcept { mPoseBudgetBytes = bytesPerBeat; }
    [[nodiscard]] std::size_t PoseBudget() const noexcept { return mPoseBudgetBytes; }
    /** Plan WP8.2: `army`'s client's cameras as it last reported them (WP11.1), from any thread. */
    void SetCameras(std::size_t army, std::vector<SCameraReport> cameras);
    /** Plan WP8.2: units a view owes a pose to, summed over the views, as of their last lanes. */
    [[nodiscard]] std::size_t OwedPoses() const;
    /**
     * Plan WP8.2's check: each view's pose lane is decoded into a copy of what its client holds (a whole unit
     * replaces its bones, a change adds to them), and every held unit it doesn't owe a pose is compared with the
     * server's sent bones. For tests: it keeps every client's bones.
     */
    void EnablePoseCheck() noexcept { mPoseCheck = true; }
    /** "N unit-beats compared, M differ, K changes to a unit the client held no pose of", with `EnablePoseCheck`. */
    [[nodiscard]] std::string PoseCheckReport() const;

  protected:
    /** The bytes of a view's lanes on the last beat. */
    [[nodiscard]] std::uint32_t ClientBytes(const std::size_t army) const { return mClients[army].bytes; }
    /** Lanes of a view that didn't encode since the last call. */
    [[nodiscard]] std::uint64_t TakeClientFailures(const std::size_t army) { return std::exchange(mClients[army].failures, 0u); }

    void UninstallRouting();

  private:
    /** What one view's client received last (its frame is held by CViewFrames). */
    struct SClient
    {
      std::vector<wire::SArmyRecord> armies;
      bool haveArmies = false;
      std::vector<std::uint16_t> grids; // the slots it received last beat (`SBeatGrid::key`)
      std::vector<std::uint16_t> gridsNext;
      wire::BitWriter lua;              // this beat's Lua lane, which is ready before the others
      wire::BitWriter teamFrame;        // a team's view: this beat's frame, for its players' messages
      std::vector<std::uint32_t> poseUnits;     // the units it held last beat (`HeldUnitIds`), for the pose lane
      std::vector<std::uint32_t> poseUnitsNext;
      std::vector<CPoseTracker::SOwedPose> owedPoses; // plan WP8.2: units whose pose changes it didn't get yet
      std::vector<float> poseKeys;              // and this beat's order keys for `poseUnitsNext`
      std::uint32_t poseBeat = 0;               // its pose lanes so far, the owed units' clock
      std::unordered_map<std::uint32_t, std::vector<wire::SPoseBone>> poseCopy; // `EnablePoseCheck`: what it holds
      std::uint64_t teamHash = 0;       // and on a check's beat its hash
      bool fresh = false;               // `RequestFresh`
      std::uint32_t bytes = 0;          // this beat
      std::uint64_t failures = 0;       // since `TakeClientFailures`
    };

    /** One grid: every client that holds last beat's gets the same delta, encoded once. */
    struct SBeatGrid
    {
      wire::SGridSlot slot;                     // who and which; no cells
      std::uint32_t receivers = 0;              // the views that get it, by bit
      moho::CIntelGrid* source = nullptr;       // the sim's grid (its change flags are cleared as it is read)
      std::vector<std::uint64_t> seen;          // its cells set as of this beat, a bit each (`wire::GridSeenWords`), once `delta` is written
      wire::BitWriter delta;                    // the slot against last beat's cells
      std::uint16_t key = 0;                    // army and kind
      bool fresh = true;                        // no cells to go from: every client gets it whole
      bool skipped = false;                     // no view received it, so `seen` wasn't kept up
    };

    void Send(std::size_t army);

    std::vector<SClient> mClients;
    std::size_t mPoseBudgetBytes = 0;
    bool mPoseCheck = false;
    std::atomic<std::uint64_t> mPoseCheckUnits{0};
    std::atomic<std::uint64_t> mPoseCheckDiffers{0};
    std::atomic<std::uint64_t> mPoseCheckOrphanChanges{0};
    /** `EnablePoseCheck`: `lane` (this beat's, encoded) applied to `client`'s copy, then compared. */
    void CheckPoses(SClient& client, const wire::BitWriter& lane);
    mutable std::mutex mCamerasLock;                     // `mCameras` is written by the network thread
    std::vector<std::vector<SCameraReport>> mCameras;    // per army
    std::vector<SBeatGrid> mBeatGrids; // every army's grids, in army order; they keep their cells from beat to beat
    bool mLuaRouting = false;
    bool mLuaSeparately = false;
    std::string mLuaRoutingDump;
    std::unique_ptr<CSyncRouter> mRouter; // made once the army count is known
  };
} // namespace faf::remote
