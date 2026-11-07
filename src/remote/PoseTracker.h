#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <unordered_map>
#include <vector>

#include "remote/wire/PoseLane.h"

// Engine addition, server mode (plan WP8.1, research/WP8-pose-lane.md): the units' animation poses for a server's
// views. Once a beat, on the sim thread, every unit's current pose is compared bone by bone with what was last sent
// of it; a bone that moved past the tolerance (research/M0.3-changed-bones.md: 0.001 in position, 0.0001 in a
// quaternion component) or changed its flags is sent and becomes the new value. Every client that held the unit since
// holds those values, so each view's lane is that beat's changed bones of the units its client held last beat, and
// every bone of a unit new to it. The pipeline's threads read the beat's results until the next beat's `Refresh`.

namespace moho
{
  class CAniActor;
  class CAniPose;
  class Entity;
  class Unit;
}

namespace faf::remote
{
  class CPoseTracker
  {
  public:
    CPoseTracker() = default;
    CPoseTracker(const CPoseTracker&) = delete;
    CPoseTracker& operator=(const CPoseTracker&) = delete;
    ~CPoseTracker();

    /**
     * #118: from now on the animation step tells this tracker which bones it changed (`moho::gAniPoseUpdatedHook`), while
     * they're in cache on the pose jobs' threads; `Refresh` then reads only those. One tracker per process.
     */
    void InstallHook();
    /** A bone's local transform and flags as last read, to skip the ones that didn't change at all. */
    struct SRawBone
    {
      float transform[7]; // the `VTransform` as stored
      std::uint32_t flags;
    };

    struct SUnit;

    /**
     * What the animation hook reads and writes of one unit, during the sim's tick (the pipeline's threads never read
     * it): the bones as last read, a bit per bone whose raw value changed since, and whether the hook saw an update.
     */
    struct SHookState
    {
      std::vector<SRawBone> raw;
      std::vector<std::uint64_t> dirty;           // a bit per bone that moved past the tolerance: `pending` holds it
      std::vector<wire::SPoseBone> mirror;        // `SUnit::sent` as of the last beat (the hook's own copy)
      std::vector<wire::SPoseBone> pending;       // a marked bone's quantised value, for `Refresh`
      const void* skeleton = nullptr;              // the hook only marks a pose of this skeleton and `raw`'s size
      const moho::CAniActor* indexedUnder = nullptr; // its key in the hook's index, if any
      SUnit* owner = nullptr;                      // the unit (units keep their addresses)
      bool queued = false;                         // in this beat's list of marked units
    };

    struct SUnit
    {
      std::uint32_t id = 0;
      moho::Entity* entity = nullptr;
      moho::Unit* unit = nullptr;          // null: not a unit
      const void* skeleton = nullptr;      // the skeleton of the pose read last
      const moho::CAniActor* actor = nullptr; // the actor read last
      std::uint8_t quietReads = 0;         // reads in a row with no enabled manipulator (past 2: not read)
      std::vector<wire::SPoseBone> sent;   // every bone as the clients that held the unit since hold it
      std::unique_ptr<SHookState> hook;    // its own address: the hook's index points at it while units move
      std::vector<std::uint16_t> changed;  // this beat's, ascending
      std::vector<wire::SPoseBone> differences; // each changed bone's step from what the clients held
      bool reset = false;                  // this beat: every client gets it whole (a new unit, or a new skeleton)
      std::uint32_t visited = 0;           // the beat (+1) `ReadAll` last listed it in
      bool dropped = false;                // left the sim this beat; freed after the beat's read
    };

    /**
     * This beat's units (as `CSharedUnitStats::Refresh` takes them: family-0 ids ascending and their entities), on
     * the sim thread; reads their poses on the sim's workers with `parallel`.
     */
    void Refresh(std::span<const std::uint32_t> ids, std::span<moho::Entity* const> entities, bool parallel);

    /**
     * One view's lane: the units of `held` (ascending ids its client holds after this beat) with a pose; whole for a
     * unit not in `heldBefore` (last beat's), reset this beat, or with `fresh` (a client that holds nothing); else
     * this beat's changed bones, if any. From any thread between `Refresh` calls.
     */
    [[nodiscard]] bool EncodeView(
      std::span<const std::uint32_t> held, std::span<const std::uint32_t> heldBefore, bool fresh, wire::BitWriter& out
    ) const;

    /** Units with a pose now (counted on asking); bones changed this beat. */
    [[nodiscard]] std::size_t PosedUnits() const noexcept;
    [[nodiscard]] std::size_t ChangedBones() const noexcept { return mChangedBones; }
    /** Since the first beat: bones changed, and beats. */
    [[nodiscard]] std::uint64_t TotalChangedBones() const noexcept { return mTotalChangedBones; }
    [[nodiscard]] std::uint64_t Beats() const noexcept { return mBeats; }
    /** Since the first beat: unit-beats read from the hook's marks (the rest were read whole or skipped). */
    [[nodiscard]] std::uint64_t TotalHookedUnits() const noexcept { return mTotalHookedUnits; }

  private:
    /** Beats over which every unit is read whole once anyway (catches what the hook can't see). */
    static constexpr std::uint32_t kSweepBeats = 16;
    /** A unit the hook marked: its marked bones' values move over. */
    static void TakeMarks(SUnit& unit);
    /** A unit read from the sim: new, or this beat's share of the sweep. */
    static void ReadUnit(SUnit& unit);
    /** `moho::gAniPoseUpdatedHook`: marks the bones of a known actor's pose that changed. */
    static void OnPoseUpdated(const moho::CAniActor& actor);
    /** A unit leaves the hook's index (sim thread, between ticks). */
    void Unindex(SUnit& unit);
    /** `Refresh`'s two parts: this beat's units over last beat's, then every unit's pose read. */
    void Merge(std::span<const std::uint32_t> ids, std::span<moho::Entity* const> entities);
    void ReadAll(bool parallel);

    // Ascending ids. Each unit has its own address, so a beat whose units come and go moves only pointers.
    std::vector<std::unique_ptr<SUnit>> mUnits;
    std::vector<std::unique_ptr<SUnit>> mNext;
    std::unordered_map<const moho::CAniActor*, SHookState*> mByActor; // read by the hook during ticks
    bool mHooked = false;
    // #118: units the hook marked this tick (each once), so a beat visits only these, new units and a sweep share.
    std::vector<SUnit*> mMarked;              // sized to the units before each tick
    std::atomic<std::size_t> mMarkedCount{0};
    std::vector<SUnit*> mNewUnits;            // made by this beat's merge
    std::vector<SUnit*> mTouched;             // last beat's units with changes, to clear
    struct SWork
    {
      SUnit* unit;
      bool marked;
    };
    std::vector<SWork> mWork;
    bool mFirstRead = true;
    std::uint64_t mTotalHookedUnits = 0; // unit-beats whose bones came from the hook's marks
    std::size_t mChangedBones = 0;
    std::uint64_t mTotalChangedBones = 0;
    std::uint64_t mBeats = 0;
  };
} // namespace faf::remote
