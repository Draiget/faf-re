#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/ESquadClass.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  class Sim;
  class CPlatoon;

  /**
   * Recovered `CSquad` runtime object.
   *
   * Address context (allocator/ctor lanes):
   * - 0x00725580 (FUN_00725580, Moho::CSquad::operator new) — heap allocates
   *   the 0x60-byte squad object on a parent platoon.
   * - 0x00723E70 (FUN_00723E70, Moho::CSquad::CSquad) — initializes the unit
   *   storage lane, copies in the squad-class tag and optional name, and
   *   intrusively links the unit-set onto the sim's entity-DB list.
   * - 0x00723F70 (FUN_00723F70, Moho::CSquad::~CSquad) — releases dynamic
   *   unit storage, destroys category list, unlinks from the entity-DB list.
   *
   * Each squad owns one `SEntitySetTemplateUnit` (0x28 bytes including its
   * intrusive ring-list head and the inline 4-entity buffer) and a category
   * vector. Squads belong to a `CPlatoon` and are stored in the platoon's
   * `mSquadList` fastvector.
   */
  class CSquad
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00723E70 (FUN_00723E70, Moho::CSquad::CSquad)
     *
     * What it does:
     * Initializes the unit storage lane to its inline state, captures the
     * squad-class tag, copies the optional name into `mName`, and links the
     * intrusive unit-set node into the sim's entity-DB list at the third
     * (per-squad) slot.
     */
    CSquad(ESquadClass squadClass, Sim* sim, const char* name);

    /**
     * Address: 0x00723F70 (FUN_00723F70, Moho::CSquad::~CSquad)
     *
     * What it does:
     * Releases any heap-backed unit storage, destroys the per-category
     * filter vector, restores `mName` to the empty SSO state, and unlinks
     * the unit-set node from its intrusive ring.
     */
    ~CSquad();

    /**
     * Address: 0x00725580 (FUN_00725580, Moho::CSquad::operator new)
     *
     * What it does:
     * Heap-allocates one 0x60-byte squad on the supplied parent platoon,
     * runs the squad constructor, and pushes the new squad pointer onto the
     * platoon's `mSquadList` fastvector (growing it if needed).
     */
    [[nodiscard]] static CSquad* AllocateOnPlatoon(CPlatoon* parentPlatoon, ESquadClass squadClass, const char* name);

    /**
     * Address: 0x00724220 (FUN_00724220, Moho::CSquad::CountUnitsWithBP)
     *
     * What it does:
     * Counts live squad units whose blueprint id matches `blueprintId`
     * case-insensitively.
     */
    [[nodiscard]] int CountUnitsWithBP(const char* blueprintId) const;

    /**
     * Address: 0x007242B0 (FUN_007242B0, Moho::CSquad::CountUnitsInCategory)
     *
     * What it does:
     * Counts live squad units whose blueprint category bit belongs to
     * `categorySet`.
     */
    [[nodiscard]] int CountUnitsInCategory(const EntityCategorySet* categorySet) const;

    /**
     * Address: 0x007244E0 (FUN_007244E0, Moho::CSquad::CanAttackTarget)
     *
     * What it does:
     * Scans live squad units and returns true as soon as any unit attacker can
     * pick the supplied target entity. Empty slots, dead units, and units
     * without attackers are skipped.
     */
    [[nodiscard]] bool CanAttackTarget(Unit* target);

    /**
     * Address: 0x00724750 (FUN_00724750, Moho::CSquad::HasUnitWithState)
     *
     * What it does:
     * Returns true when any live unit in this squad reports the requested
     * unit-state lane.
     */
    [[nodiscard]] bool HasUnitWithState(EUnitState state) const;

    /**
     * Address: 0x00724350 (FUN_00724350, Moho::CSquad::AppendUnitsWithBP)
     *
     * What it does:
     * Walks this squad's unit list and appends every live (not dead, not
     * destroying, not under-construction) unit whose blueprint id matches
     * `blueprintId` (case-insensitive) into `outUnits`, stopping after
     * `maxCount` matches have been added.
     */
    void AppendUnitsWithBP(const char* blueprintId, int maxCount, SEntitySetTemplateUnit& outUnits);

    /**
     * Address: 0x00724400 (FUN_00724400, Moho::CSquad::AppendUnitsInCategory)
     *
     * What it does:
     * Walks this squad's unit list and appends every live (not dead, not
     * destroying, not under-construction) unit whose blueprint category bit is
     * present in `categorySet`, stopping once `maxCount` matches are added.
     */
    void AppendUnitsInCategory(const EntityCategorySet* categorySet, int maxCount, SEntitySetTemplateUnit& outUnits);

    /**
     * Address: 0x00724550 (FUN_00724550, Moho::CSquad::FitsAt)
     *
     * What it does:
     * Tests whether every live squad unit can fit its footprint at `position`
     * against terrain occupancy using per-motion-type layer checks.
     */
    [[nodiscard]] bool FitsAt(const Wm3::Vec3f& position) const;

    /**
     * Address: 0x00724020 (FUN_00724020, Moho::CSquad::GetCenter)
     *
     * What it does:
     * Zeros the output vector, accumulates every unit position in this squad,
     * and returns the averaged center pointer. Empty squads return the zero
     * vector immediately.
     */
    [[nodiscard]] Wm3::Vector3f* GetCenter(Wm3::Vector3f* outPos) const;

  public:
    Sim* mSim;                                                // +0x00
    SEntitySetTemplateUnit mUnits;                            // +0x04 (size 0x28)
    ESquadClass mSquadClass;                                  // +0x2C
    msvc8::string mName;                                      // +0x30 (size 0x1C)
    msvc8::vector<EntityCategorySet> mCats;                   // +0x4C (size 0x10)
    std::uint32_t mPad_0x5C;                                  // +0x5C (alignment tail; binary always-zero observed)
  };

  static_assert(offsetof(CSquad, mSim) == 0x00, "CSquad::mSim offset must be 0x00");
  static_assert(offsetof(CSquad, mUnits) == 0x04, "CSquad::mUnits offset must be 0x04");
  static_assert(offsetof(CSquad, mSquadClass) == 0x2C, "CSquad::mSquadClass offset must be 0x2C");
  static_assert(offsetof(CSquad, mName) == 0x30, "CSquad::mName offset must be 0x30");
  static_assert(offsetof(CSquad, mCats) == 0x4C, "CSquad::mCats offset must be 0x4C");
  static_assert(sizeof(CSquad) == 0x60, "CSquad size must be 0x60");
} // namespace moho
