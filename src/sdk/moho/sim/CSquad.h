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
     * Address: 0x006DE1C0 (FUN_006DE1C0, Moho::CSquad::SetPrioritizedTargetList)
     *
     * What it does:
     * Replaces this squad's prioritized target-category vector (`mCats`) with
     * the contents of `categorySource`. The fast-path (capacity already large
     * enough) does an in-place vector assignment; otherwise the existing
     * storage is destroyed and a fresh buffer is allocated to fit the new
     * size. Self-assignment is a no-op.
     */
    void SetPrioritizedTargetList(const msvc8::vector<EntityCategorySet>& categorySource);

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

  /**
   * VFTABLE: 0x00E31B78 (`??_7CSquadSerializer@Moho@@6B@`)
   *
   * `Init()`/`Deserialize()`/`Serialize()` are each ICF-shared with
   * `gpg::SerSaveLoadHelper<Moho::CSquad>`'s own bodies (two vftable-slot
   * data xrefs land on each address, and IDA independently resolves
   * Deserialize/Serialize's qualified name as `Moho::CSquadSerializer::`,
   * not the template's). But the confirmed `__xc_a`-reachable ctor
   * (0x00BDAC20) installs `CSquadSerializer`'s OWN vtable
   * (`??_7CSquadSerializer@Moho@@6B@`), not the template's -- and a
   * distinct `CSquadSerializer@Moho` vtable/RTTI symbol could not exist at
   * all if this were a pure `using X = SerSaveLoadHelper<T>` alias
   * (aliases never introduce a new type, let alone a new vtable).
   * `CSquadSerializer` is therefore a real concrete class, same precedent
   * as `Rect2iSerializer`/`Box3fSerializer`/`Moho::SPhysBodySerializer` --
   * not a template instantiation in disguise. (The previous `using`
   * modeling only checked that the callback bodies matched the template;
   * it never checked which vtable the live ctor actually installs, which
   * is what this class-level comment previously got backwards.) Two dead
   * zero-xref COMDAT duplicate ctors: 0x007249D0 (installs this class's
   * own vtable, never called) and 0x0072A5C0 (installs the template's
   * vtable onto this same global, never called either).
   */
  class CSquadSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDAC20 (FUN_00BDAC20, dynamic initializer for the global
     * `CSquadSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CSquadSerializer();

    /**
     * Address: 0x00C00500 (`??1CSquadSerializer@Moho@@QAE@@Z`,
     * Moho::CSquadSerializer::~CSquadSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CSquadSerializer();

    /**
     * Address: 0x007249B0 (FUN_007249B0, Moho::CSquadSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load flow into `CSquad::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x007249C0 (FUN_007249C0, Moho::CSquadSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save flow into `CSquad::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0072A5F0 (FUN_0072A5F0, Moho::CSquadSerializer::Init)
     *
     * What it does:
     * Binds load/save callbacks into `CSquad`'s reflected RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(offsetof(CSquadSerializer, mLoadCallback) == 0x0C, "CSquadSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(CSquadSerializer, mSaveCallback) == 0x10, "CSquadSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(CSquadSerializer) == 0x14, "CSquadSerializer size must be 0x14");

  /**
   * VFTABLE: 0x00E31B68 (`??_7CSquadConstruct@Moho@@6B@`)
   *
   * Same ICF-shared-`Init()`-with-a-dead-template-twin shape as
   * `CSquadSerializer` above: `Init()` (FUN_0072A570) is shared with
   * `gpg::SerConstructHelper<Moho::CSquad>::Init()` (confirmed via two
   * vftable-slot data xrefs into that one address). That template's own
   * separately-emitted ctor (FUN_0072A540) plus a second dead out-of-line
   * copy of this class's own ctor (FUN_00724880) both have zero incoming
   * xrefs and are `skip`; the confirmed `__xc_a`-reachable ctor is
   * 0x00BDABE0, which installs this class's own vtable.
   */
  class CSquadConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDABE0 (FUN_00BDABE0, dynamic initializer for the global
     * `CSquadConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields.
     */
    CSquadConstruct();

    /**
     * Address: 0x00C004D0 (FUN_00C004D0, Moho::CSquadConstruct::~CSquadConstruct)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CSquadConstruct();

    /**
     * Address: 0x0072A570 (FUN_0072A570, Moho::CSquadConstruct::Init)
     *
     * What it does:
     * Binds the construct/delete callbacks into `CSquad`'s reflected RTTI.
     * Mirrors the binary's single `!type->mSerConstructFunc` assert (no
     * separate delete-slot assert), confirmed from raw disassembly.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeleteCallback;         // +0x10
  };

  static_assert(
    offsetof(CSquadConstruct, mConstructCallback) == 0x0C, "CSquadConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CSquadConstruct, mDeleteCallback) == 0x10, "CSquadConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CSquadConstruct) == 0x14, "CSquadConstruct size must be 0x14");
} // namespace moho
