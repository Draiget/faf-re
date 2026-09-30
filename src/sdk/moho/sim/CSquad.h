#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/ESquadClass.h"
#include "Wm3Vector3.h"

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus

namespace gpg
{
  class RType;
  class ReadArchive;
  class WriteArchive;
}

namespace gpg
{
  class ReadArchive;
  class RRef;
  class SerConstructResult;
} // namespace gpg

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
     * Address: 0x00723E00 (FUN_00723E00, Moho::CSquad::CSquad)
     *
     * What it does:
     * Default construction for the serializer: null sim, unassigned class,
     * empty unit set (self-linked ring, inline storage), empty name and
     * category vector. +0x04 is left untouched, as in the binary.
     */
    CSquad();

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
     * Address: 0x00723A50 (FUN_00723A50, copy_CSquadUnits_into_EntitySet)
     *
     * IDA signature:
     * Moho::SEntitySetTemplateUnit *__usercall sub_723A50@<eax>(
     *   Moho::SEntitySetTemplateUnit *result@<esi>, Moho::CSquad *this@<edx>);
     *
     * What it does:
     * Returns a copy of `mUnits` (copy constructor 0x00579500) in the
     * caller's return slot. The platoon's order functions take one before
     * commanding a squad; `CPlatoon::GetPlatoonUnits` takes one per squad.
     * Emitted first in the translation unit, ahead of `CPlatoon::GetClass`,
     * as an inline from this header is.
     */
    [[nodiscard]] SEntitySetTemplateUnit GetUnitSet() const
    {
      return mUnits;
    }

    /**
     * What it does:
     * Returns whether `unit` is one of this squad's units, by a linear scan
     * (`p ? p - 8 : 0` per entry). Never emitted out of line: inlined into
     * `CPlatoon::IsInPlatoon` (0x007251D0), `CPlatoon::GetSquadClass`
     * (0x00725220) and `CPlatoon::RemoveUnit` (0x007253B0). Not
     * `mUnits.ContainsUnit`, which is the binary search.
     */
    [[nodiscard]] bool HasUnit(const Unit* unit) const;

    /**
     * Address: 0x00724150 (FUN_00724150, Moho::CSquad::RemoveUnit)
     *
     * IDA signature:
     * void __usercall Moho::CSquad::RemoveUnit(Moho::CSquad *this@<ebx>, Moho::Unit *unit@<eax>);
     *
     * What it does:
     * Erases the first entry that is `unit`, closing the gap with `memmove`.
     */
    void RemoveUnit(Unit* unit);

    /**
     * Address: 0x007241C0 (FUN_007241C0)
     *
     * IDA signature:
     * void __usercall sub_7241C0(Moho::CSquad *this@<eax>, Moho::SEntitySetTemplateUnit *units@<edi>);
     *
     * What it does:
     * `RemoveUnit` for every unit in `units`. The out-of-line copy has no
     * caller; it is inlined into `CPlatoon::ReturnUnitsTo` (0x00725410) and
     * `CPlatoon::DestroySquads` (0x00726210).
     */
    void RemoveUnits(const SEntitySetTemplateUnit& units);

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
     * Returns true when any live unit in this squad is in `state`.
     */
    [[nodiscard]] bool HasUnitWithState(EUnitState state) const;

    /**
     * Address: 0x007247A0 (FUN_007247A0, Moho::CSquad::UnitHasOrder)
     *
     * What it does:
     * Returns true unless some live unit has a command at the head of its
     * queue. The IDB name reads the result backwards.
     */
    [[nodiscard]] bool IsIdle() const;

    /**
     * Address: 0x00724820 (FUN_00724820, Moho::CSquad::Stop)
     *
     * What it does:
     * Clears every live unit's command queue (no null test on the queue) and
     * stops its attacker, when it has one.
     */
    void Stop();

    /**
     * Address: 0x0072B700 (FUN_0072B700, Moho::CSquad::GetUnits)
     *
     * What it does:
     * Fills `outTable` with this squad's member units as a Lua array, in
     * storage order. Returns `outTable`.
     */
    LuaPlus::LuaObject* GetUnits(LuaPlus::LuaObject* outTable, LuaPlus::LuaState* state) const;

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

    /**
     * Address: 0x00724810 (FUN_00724810)
     *
     * IDA signature:
     * int __userpurge sub_724810@<eax>(std::vector_EntityCategory *categories@<eax>, Moho::CSquad *this);
     *
     * What it does:
     * `mCats = categories`: moves `this` to `&mCats` in EAX and calls
     * `msvc8::vector<EntityCategorySet>::operator=` (0x006DE1C0). The
     * out-of-line copy has no caller; `CPlatoon::SetPrioritizedTargetList`
     * (0x00725990, itself inlined into the Lua binding 0x0072E940) inlines it.
     */
    void SetPrioritizedTargetList(const msvc8::vector<EntityCategorySet>& categories);

    /**
     * Address: 0x00724920 (FUN_00724920)
     *
     * What it does:
     * Builds a new `CSquad` for an archive load and hands it back unowned; its
     * members are loaded over it afterwards.
     */
    static void MemberConstruct(
      gpg::ReadArchive& archive, int version, const gpg::RRef& ownerRef, gpg::SerConstructResult& result
    );

    /**
     * Address: 0x0072B200 (FUN_0072B200, Moho::CSquad::MemberDeserialize)
     *
     * What it does:
     * Loads `mSim`, `mUnits`, `mSquadClass`, `mName`, then `mCats` in binary
     * archive order.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0072B2E0 (FUN_0072B2E0, Moho::CSquad::MemberSerialize)
     *
     * What it does:
     * Saves `mSim`, `mUnits`, `mSquadClass`, `mName`, then `mCats` in binary
     * archive order.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

  public:
    Sim* mSim;                                                // +0x00
    std::uint32_t mPad_0x04;                                  // +0x04 (binary leaves this uninitialised; reserved/unused slot)
    SEntitySetTemplateUnit mUnits;                            // +0x08 (size 0x28)
    ESquadClass mSquadClass;                                  // +0x30
    msvc8::string mName;                                      // +0x34 (size 0x1C)
    msvc8::vector<EntityCategorySet> mCats;                   // +0x50 (size 0x10)
  };

  static_assert(offsetof(CSquad, mSim) == 0x00, "CSquad::mSim offset must be 0x00");
  static_assert(offsetof(CSquad, mUnits) == 0x08, "CSquad::mUnits offset must be 0x08");
  static_assert(offsetof(CSquad, mSquadClass) == 0x30, "CSquad::mSquadClass offset must be 0x30");
  static_assert(offsetof(CSquad, mName) == 0x34, "CSquad::mName offset must be 0x34");
  static_assert(offsetof(CSquad, mCats) == 0x50, "CSquad::mCats offset must be 0x50");
  static_assert(sizeof(CSquad) == 0x60, "CSquad size must be 0x60");

} // namespace moho
