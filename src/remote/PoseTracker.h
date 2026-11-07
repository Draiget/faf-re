#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
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
    /** A bone's local transform and flags as last read, to skip the ones that didn't change at all. */
    struct SRawBone
    {
      float transform[7]; // the `VTransform` as stored
      std::uint32_t flags;
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
      std::vector<SRawBone> raw;           // every bone as last read
      std::vector<std::uint16_t> changed;  // this beat's, ascending
      std::vector<wire::SPoseBone> differences; // each changed bone's step from what the clients held
      bool reset = false;                  // this beat: every client gets it whole (a new unit, or a new skeleton)
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

    /** This beat: units with a pose, bones changed, units reset. */
    [[nodiscard]] std::size_t PosedUnits() const noexcept { return mPosed; }
    [[nodiscard]] std::size_t ChangedBones() const noexcept { return mChangedBones; }
    /** Since the first beat: bones changed, and beats. */
    [[nodiscard]] std::uint64_t TotalChangedBones() const noexcept { return mTotalChangedBones; }
    [[nodiscard]] std::uint64_t Beats() const noexcept { return mBeats; }

  private:
    static void ReadUnit(SUnit& unit);
    /** `Refresh`'s two parts: this beat's units over last beat's, then every unit's pose read. */
    void Merge(std::span<const std::uint32_t> ids, std::span<moho::Entity* const> entities);
    void ReadAll(bool parallel);

    std::vector<SUnit> mUnits; // ascending ids
    std::vector<SUnit> mNext;
    std::size_t mPosed = 0;
    std::size_t mChangedBones = 0;
    std::uint64_t mTotalChangedBones = 0;
    std::uint64_t mBeats = 0;
  };
} // namespace faf::remote
