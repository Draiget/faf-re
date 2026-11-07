#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <memory>
#include <unordered_set>
#include <utility>
#include <vector>

#include "remote/FrameBuilder.h"
#include "remote/PoseTracker.h"
#include "remote/ViewIdMap.h"
#include "remote/ViewJobs.h"
#include "gpg/core/containers/ChunkedVector.h"
#include "remote/ViewPackets.h"
#include "remote/VisibilityOracle.h"
#include "remote/wire/EntityFrame.h"

// Engine addition, server mode (plan WP5.2): per view and beat, the frame the server sends one
// army. Each army's rebuilt packet (remote/ViewPackets.h, equal to the lockstep client's) is
// applied to that army's own `CViewFrameBuilder`, whose world then holds what that client holds:
// an entity the beat's walk did not sync keeps its record from the beat it last changed, so
// unchanged entities carry the same packed data as the previous frame (a unit's detail and
// stats are shared values). The frame is that world less what the visibility oracle withholds:
// a plain entity in mode ReconGrid out of the view's sight (`CanViewSee`, plan §6). Records the
// sim no longer has (orphaned props, kept until the client sees their spot) stay.
//
// With `EnableIdMaps` (plan WP5.9) every frame then goes through its view's `CViewIdMap`: blips,
// foreign projectiles and foreign command ids are renumbered per view. Off until inbound
// translation (WP5.10) exists, because a client would otherwise send back ids the sim lacks.

namespace moho
{
  class EntityDB;
}

namespace faf::remote
{
  class CViewFrames : public CViewPackets
  {
  public:
    CViewFrames(const wire::SContentTables& tables, const wire::SFrameCodec& codec);
    ~CViewFrames() override;

    /** Renumbers the frames' ids per view from the next beat on (remote/ViewIdMap.h). */
    void EnableIdMaps() noexcept { mIdMapsOn = true; }
    [[nodiscard]] bool IdMapsOn() const noexcept { return mIdMapsOn; }
    /** `army`'s id map (with `EnableIdMaps`, once a beat has been built): its team's, with teams. */
    [[nodiscard]] const CViewIdMap& IdMap(std::int32_t army) const { return *mIdMaps[TeamSlotOf(static_cast<std::size_t>(army))]; }
    /** The views built so far (0 before the first beat). */
    [[nodiscard]] std::size_t ViewCount() const noexcept { return mIdMaps.size(); }
    /**
     * Plan WPR.35: `CViewPackets::EnableTeams` for a server: needs `EnableHeldFrames` without its check, and
     * `EnablePipeline`, which finishes a team's view and then its players' on one thread, as they share an id map.
     */
    void EnableTeamViews() noexcept
    {
      if (mHeldOn && !mHeldCheck && mJobs != nullptr) {
        EnableTeams();
      }
    }
    /**
     * Plan WP11 step 4, before the first beat: every view's frames name their sounds, underlays, custom names,
     * range visuals and unit stats in `session`, one table for all of them; each beat's new deposits and terrain
     * edits are queued there once (`SessionEdits`). Whoever sends the frames sends `session`'s pending record
     * to every player before the beat's frames (`OnViewFrames`).
     */
    void EnableSessionTables(wire::CSessionTableWriters& session, const std::uint32_t statsEveryBeats = kStatsEveryBeats) noexcept
    {
      mSession = &session;
      mSharedRecords.SetSessionTables(&session);
      mSharedStats.SetReadEvery(statsEveryBeats);
    }
    /**
     * Plan WP11.5 (#178), on the sim thread before a beat's frames are encoded: the sim rate and the server's clock
     * (ms) the held frames' headers carry, for the client's beat clock.
     */
    void SetFrameClock(const std::int32_t simRate, const std::uint32_t serverMs) noexcept
    {
      mFrameSimRate = simRate;
      mFrameServerMs = serverMs;
    }
    /** Plan WP8.1, before the first beat: the units' poses are tracked each beat for the views' pose lanes. */
    void EnablePoses()
    {
      mPosesOn = true;
      mPoses.InstallHook(); // #118: the animation step marks the bones it changed
    }
    [[nodiscard]] bool PosesOn() const noexcept { return mPosesOn; }
    [[nodiscard]] const CPoseTracker& Poses() const noexcept { return mPoses; }
    /**
     * The units `army`'s client holds after this beat (its own view's and, with teams, its team's), ascending. In
     * `OnViewReady` or after `FinishViews`.
     */
    void HeldUnitIds(std::size_t army, std::vector<std::uint32_t>& out) const;
    /** `CSharedUnitStats::SetReadEvery`'s default: a unit's stats at most 0.3 s late (server `--stats-every`). */
    static constexpr std::uint32_t kStatsEveryBeats = 4;
    /** `--stats-every <beats>` (server and headless view bench): 1 reads every unit's stats every beat. */
    void SetStatsEveryBeats(const std::uint32_t beats) noexcept { mSharedStats.SetReadEvery(beats); }
    [[nodiscard]] wire::CSessionTableWriters* SessionTables() const noexcept { return mSession; }
    [[nodiscard]] const CSessionEditCollector& SessionEdits() const noexcept { return mEdits; }
    /** The sim of the last beat built (null before it); for checks that run on the sim thread. */
    [[nodiscard]] moho::Sim* LastSim() const noexcept { return mLastSim; }

    /** The last beat's frame for `army`. */
    [[nodiscard]] const wire::SViewFrame& Frame(std::int32_t army) const { return mFrames[static_cast<std::size_t>(army)]; }
    /**
     * The frame `army` had the beat before (moved aside, not copied); null before its second
     * beat. A client that received every frame holds it: the server's baseline without loss.
     */
    [[nodiscard]] const wire::SViewFrame* PreviousFrame(std::int32_t army) const
    {
      const auto index = static_cast<std::size_t>(army);
      return mHavePrevious[index] ? &mPreviousFrames[index] : nullptr;
    }
    /**
     * Plan WPR.35: from the next beat on, each view keeps its frame between beats and each beat
     * handles only the records that changed, so a record that did not change is neither copied,
     * translated nor compared. `Frame` and `PreviousFrame` then stay empty: a server asks
     * `HeldCount` and `EncodeHeldFrame`. With `check` every view's frame is also built whole
     * (with its own id map) and compared, record by record and byte by byte (`HeldMismatches`).
     */
    void EnableHeldFrames(const bool check = false) noexcept
    {
      mHeldOn = true;
      mHeldCheck = check;
      SetDirectUpdates(true);
      SetSharedRecords(&mSharedRecords);
    }
    [[nodiscard]] bool HeldFramesOn() const noexcept { return mHeldOn; }
    /**
     * Plan WPR.35, with `EnableHeldFrames` and without its check: what's left of a view's beat once
     * its records are applied doesn't read the sim, so `threads` threads do it while the sim goes on
     * to its next beat. `FinishViews` waits for it; a new beat's views do so first. Frames and bytes
     * stay the same; whatever reads them (`HeldCount`, `EncodeHeldFrame`) must wait, or be in
     * `OnViewReady`.
     */
    void EnablePipeline(unsigned int threads);
    [[nodiscard]] bool PipelineOn() const noexcept { return mJobs != nullptr; }
    /** Waits for the last beat's view work. Returns the seconds waited. */
    double FinishViews();
    /** The records in `army`'s last frame (with `EnableHeldFrames`). */
    [[nodiscard]] std::size_t HeldCount(const std::int32_t army) const { return mHeld[static_cast<std::size_t>(army)].count; }
    /** `--view-dump`: from now on, every 2000 beats, what each player's client holds, by sim id with a hash of each record. */
    void SetViewDump(std::FILE* const file) noexcept { mViewDump = file; }
    /** `army`'s last frame against the one before, as `wire::EncodeFrame` writes it. */
    [[nodiscard]] bool EncodeHeldFrame(std::int32_t army, wire::BitWriter& writer) const;
    /**
     * `army`'s last frame whole, against nothing, with the same frame id: for a client that lost what it held
     * (plan WP14.1). The next frame is encoded against this one as for anyone else.
     */
    [[nodiscard]] bool EncodeWholeHeldFrame(std::int32_t army, wire::BitWriter& writer) const;
    /** Plan WPR.30: `wire::HashRecord` summed over what `army`'s client holds after its last frame. */
    [[nodiscard]] std::uint64_t HeldFrameHash(std::int32_t army) const;
    /**
     * With `EnableHeldFrames`, between a beat's views: whether `army`'s client holds a record with this
     * id, or held one within `CViewIdMap::kInboundGraceBeats` (its order may be on its way).
     */
    [[nodiscard]] bool ViewHoldsEntity(std::size_t army, std::uint32_t id) const;
    /** `simId` as `view`'s client knows it, for an id written outside its frames (plan WP6.10). */
    [[nodiscard]] std::uint32_t ViewEntityId(std::size_t view, std::uint32_t simId);
    /** Differences the check found (should stay 0). */
    [[nodiscard]] std::uint64_t HeldMismatches() const noexcept;

    /** Records `army`'s client holds that its last frame withheld. */
    [[nodiscard]] std::uint32_t Withheld(std::int32_t army) const { return mWithheld[static_cast<std::size_t>(army)]; }

  protected:
    void OnViewPackets(moho::Sim& sim) override;

    /**
     * The views' frames of a sealed beat are ready (`Frame`). With a pipeline they are not yet:
     * this is the last call of the beat that may read the sim, and the frames come later.
     */
    virtual void OnViewFrames(moho::Sim& sim) { (void)sim; }
    /**
     * Other work of the beat that reads the stopped sim and nothing of the frames: on the sim thread,
     * before the frames, says how many jobs there are; `RunSideJob` then runs each on the workers in
     * the frames' batch, so work that mostly waits on memory overlaps theirs (plan #118).
     */
    virtual std::size_t PrepareSideJobs(moho::Sim& sim) { (void)sim; return 0u; }
    virtual void RunSideJob(const std::size_t index) { (void)index; }
    /** With a pipeline, on one of its threads: `army`'s frame is ready. Must not read the sim. */
    virtual void OnViewReady(const std::size_t army) { (void)army; }
    /** With a pipeline, on the sim thread: every view's `OnViewReady` of the last beat is over. */
    virtual void OnViewsFinished() {}

    void OnBeatStarting() override { (void)FinishViews(); }
    /** The beat `OnViewPackets` last handled. */
    [[nodiscard]] std::uint32_t ViewBeat() const noexcept { return mViewBeat; }
    /** How long the sim thread waited for the last beat's view work (in `OnViewsFinished`). */
    [[nodiscard]] double ViewWaitSeconds() const noexcept { return mViewWaitSeconds; }

  private:
    /** One view's frame kept between beats, and what its last beat changed. */
    struct SHeldView
    {
      // What the client holds is the world's record, unless the view's differs (`ownSlot`).
      gpg::core::ChunkedVector<wire::SEntityRecord> own; // in the view's ids
      std::vector<std::uint32_t> ownSlot;       // per slot: index into `own`, or `kNoOwn`
      std::vector<std::uint32_t> ownFree;       // elements of `own` no slot uses
      std::vector<std::uint8_t> sent;           // per slot: the client holds a record
      std::vector<std::uint8_t> keep;           // per slot: in this beat's frame
      std::vector<std::uint64_t> references;    // per slot: a filter of the sim ids the record names
      std::vector<std::uint32_t> referrers;     // the slots with a filter, and some that no longer have one
      std::vector<std::uint8_t> isReferrer;     // per slot: in `referrers`
      std::size_t count = 0;
      std::uint32_t frameId = 0;
      std::uint32_t baselineId = wire::kNoBaseline;
      std::uint32_t beat = 0;
      std::vector<std::uint32_t> candidates;
      std::vector<std::uint32_t> removed;
      std::deque<std::pair<std::uint32_t, std::uint32_t>> recentlyGone; // beat, id; oldest first
      std::vector<const wire::SEntityRecord*> created;
      std::vector<wire::SFrameChange> changed;
      gpg::core::ChunkedVector<wire::SEntityRecord> before; // changed `own` records as the client held them
      // With the check:
      std::unique_ptr<CViewIdMap> checkMap;
      wire::SViewFrame checkPrevious;
      bool haveCheckPrevious = false;
      std::uint64_t mismatches = 0;
    };

    /** This beat's `mEntityIndex` from last beat's and the change set; false if that isn't the sim's entities. */
    [[nodiscard]] bool AdvanceEntityIndex(const moho::EntityDB& database);
    /** This beat's `mEntityIndex` from the sim's entity map. */
    void WalkEntityIndex(const moho::EntityDB& database);
    /** Whether the view of `viewBit` keeps `id`'s record: yes for an id with no entity (an orphan). */
    [[nodiscard]] bool KeptByView(std::uint32_t id, std::uint32_t viewBit) const;
    /** The view's frame from its packet, keeping what did not change (`EnableHeldFrames`). Reads the sim. */
    void ApplyHeldFrame(moho::Sim& sim, std::size_t army, const moho::SSyncData& packet);
    /** The rest of that, from what the view keeps. Doesn't read the sim, without the check. */
    void FinishHeldFrame(std::size_t army, const moho::SSyncData& packet);
    /** The part of a view's beat `FinishHeldFrame` is, and the ids that retire. */
    void FinishFrame(std::size_t army);
    /** Writes `--view-dump`'s sample. */
    void DumpViews();
    /** Whether a slot's client holds a record now, or held one lately. */
    [[nodiscard]] bool SlotHoldsEntity(std::size_t slot, std::uint32_t id) const;
    /** A view's own-command test: the commands of its army, or with teams its whole team's. */
    [[nodiscard]] CViewIdMap::OwnCommandTest OwnCommands(std::size_t slot) const;
    /** Compares the held frame with the whole frame built from the same world. */
    void CheckHeldFrame(moho::Sim& sim, std::size_t army, const CViewIdMap::OwnCommandTest& isOwnCommand);
    /** The retirements of a beat before ids are translated, on `map`. */
    void AdvanceIdMap(std::size_t army, CViewIdMap& map);
    /** References to entities `frame` does not hold become the sim's "none" (plan WP5.12). */
    static void ClearUnheldReferences(wire::SViewFrame& frame);

    const wire::SContentTables& mTables;
    wire::SFrameCodec mCodec;
    wire::CSessionTableWriters* mSession = nullptr; // `EnableSessionTables`
    CSessionEditCollector mEdits;
    CSharedUnitStats mSharedStats;
    std::vector<std::uint32_t> mUnitIds; // this beat's units' ids (the entity index's first entries)
    bool mPosesOn = false;
    CPoseTracker mPoses;
    std::int32_t mFrameSimRate = 0;   // `SetFrameClock`
    std::uint32_t mFrameServerMs = 0;
    std::vector<std::unique_ptr<CViewFrameBuilder>> mBuilders;
    std::vector<SHeldView> mHeld;
    CSharedEntityRecords mSharedRecords;
    bool mHeldOn = false;
    bool mHeldCheck = false;
    std::vector<wire::SViewFrame> mFrames;
    std::vector<wire::SViewFrame> mPreviousFrames;
    std::vector<bool> mHavePrevious; // per view: mPreviousFrames holds a frame (written on the sim thread only)
    std::vector<bool> mBuilt;        // per view: mFrames holds a built frame (likewise)
    std::vector<std::uint32_t> mWithheld;
    /** One of the sim's entities this beat: its id and the views that keep it (`ViewsThatSee`). */
    struct SEntityKeep
    {
      std::uint32_t id;
      std::uint32_t views;
      bool readEveryBeat; // the answer depends on more than the entity (`ViewsFollowFactsAlone`)
      bool leaving;       // in its destroy pass when last read: the sim may have let go of it since
    };
    std::vector<SEntityKeep> mEntityIndex;          // the sim's entities by id, this beat
    std::vector<moho::Entity*> mEntityPointers;     // the same entities
    std::vector<SEntityKeep> mLastEntityIndex;      // and last beat
    std::vector<moho::Entity*> mLastEntityPointers;
    /** An entry of `mEntityIndex` whose answer is worked out this beat. */
    struct SEntityRead
    {
      std::uint32_t entry;
      std::uint32_t changed; // its index in `Entities()`, whose facts were read this beat, or `kNotChanged`
    };
    static constexpr std::uint32_t kNotChanged = 0xFFFFFFFFu;
    /** A sim id some view's answer changed for since last beat. No entity: every view keeps its record. */
    struct SKeepChange
    {
      std::uint32_t id;
      std::uint32_t views;   // who keeps it now
      std::uint32_t changed; // whose answer changed
    };
    std::vector<SEntityRead> mEntityReads;
    std::vector<std::uint32_t> mLeavingEntities; // ids of `SEntityKeep::leaving`
    std::vector<std::uint32_t> mGoneEntities;    // those no longer in the sim, this beat
    std::vector<SKeepChange> mKeepChanges;
    std::uint64_t mEntityIndexMismatches = 0;       // the check: answers kept that a read would change
    std::vector<std::uint32_t> mLiveCommands;     // the sim's commands by id, this beat
    std::vector<std::uint32_t> mLastCommands;     // and last beat
    std::vector<std::uint32_t> mReleasedCommands; // last beat's that are gone
    bool mIdMapsOn = false;
    moho::Sim* mLastSim = nullptr;
    std::uint32_t mViewBeat = 0;
    bool mHaveCommands = false;
    bool mJobsPending = false;
    double mViewWaitSeconds = 0.0;
    std::unique_ptr<CViewJobs> mJobs;
    std::FILE* mViewDump = nullptr;
    std::vector<std::unique_ptr<CViewIdMap>> mIdMaps;
    std::vector<std::unordered_set<std::uint32_t>> mRetiring; // per view: deleted or erased, still held
    std::vector<std::vector<std::uint32_t>> mRetired;         // per view: no longer held; retired next beat
  };
} // namespace faf::remote
