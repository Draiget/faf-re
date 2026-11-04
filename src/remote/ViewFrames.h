#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <unordered_set>
#include <utility>
#include <vector>

#include "remote/FrameBuilder.h"
#include "remote/ViewIdMap.h"
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
    /** `army`'s id map (with `EnableIdMaps`, once a beat has been built). */
    [[nodiscard]] const CViewIdMap& IdMap(std::int32_t army) const { return *mIdMaps[static_cast<std::size_t>(army)]; }
    /** The views built so far (0 before the first beat). */
    [[nodiscard]] std::size_t ViewCount() const noexcept { return mIdMaps.size(); }
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
    /** The records in `army`'s last frame (with `EnableHeldFrames`). */
    [[nodiscard]] std::size_t HeldCount(const std::int32_t army) const { return mHeld[static_cast<std::size_t>(army)].count; }
    /** `army`'s last frame against the one before, as `wire::EncodeFrame` writes it. */
    [[nodiscard]] bool EncodeHeldFrame(std::int32_t army, wire::BitWriter& writer) const;
    /** Differences the check found (should stay 0). */
    [[nodiscard]] std::uint64_t HeldMismatches() const noexcept;

    /** Records `army`'s client holds that its last frame withheld. */
    [[nodiscard]] std::uint32_t Withheld(std::int32_t army) const { return mWithheld[static_cast<std::size_t>(army)]; }

  protected:
    void OnViewPackets(moho::Sim& sim) override;

    /** The views' frames of a sealed beat are ready (`Frame`). */
    virtual void OnViewFrames(moho::Sim& sim) { (void)sim; }

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
      std::vector<const wire::SEntityRecord*> created;
      std::vector<wire::SFrameChange> changed;
      gpg::core::ChunkedVector<wire::SEntityRecord> before; // changed `own` records as the client held them
      // With the check:
      std::unique_ptr<CViewIdMap> checkMap;
      wire::SViewFrame checkPrevious;
      bool haveCheckPrevious = false;
      std::uint64_t mismatches = 0;
    };

    /** Whether the view of `viewBit` keeps `id`'s record: yes for an id with no entity (an orphan). */
    [[nodiscard]] bool KeptByView(std::uint32_t id, std::uint32_t viewBit) const;
    /** The view's frame from its packet, keeping what did not change (`EnableHeldFrames`). */
    void BuildHeldFrame(moho::Sim& sim, std::size_t army, const moho::SSyncData& packet);
    /** Compares the held frame with the whole frame built from the same world. */
    void CheckHeldFrame(moho::Sim& sim, std::size_t army, const CViewIdMap::OwnCommandTest& isOwnCommand);
    /** The retirements of a beat before ids are translated, on `map`. */
    void AdvanceIdMap(moho::Sim& sim, std::size_t army, CViewIdMap& map);
    /** References to entities `frame` does not hold become the sim's "none" (plan WP5.12). */
    static void ClearUnheldReferences(wire::SViewFrame& frame);

    const wire::SContentTables& mTables;
    wire::SFrameCodec mCodec;
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
    std::vector<SKeepChange> mKeepChanges;
    std::uint64_t mEntityIndexMismatches = 0;       // the check: answers kept that a read would change
    std::vector<std::uint32_t> mLiveCommands;     // the sim's commands by id, this beat
    std::vector<std::uint32_t> mLastCommands;     // and last beat
    std::vector<std::uint32_t> mReleasedCommands; // last beat's that are gone
    bool mIdMapsOn = false;
    moho::Sim* mLastSim = nullptr;
    std::vector<std::unique_ptr<CViewIdMap>> mIdMaps;
    std::vector<std::unordered_set<std::uint32_t>> mRetiring; // per view: deleted or erased, still held
    std::vector<std::vector<std::uint32_t>> mRetired;         // per view: no longer held; retired next beat
  };
} // namespace faf::remote
