#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/ai/EEconResourceTypeInfo.h"
#include "moho/animation/IAniManipulator.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class ReadArchive;
  class RType;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class Unit;

  /**
   * Keeps one watched bone offset between two configured extremes in step with
   * how full its army's mass or energy storage is, so a storage structure's
   * silo visibly fills and empties.
   *
   * VFTABLE: 0x00E2305C (primary, 2 slots: the deleting destructor 0x00649030
   *   and `ManipulatorUpdate` 0x00649260)
   * VFTABLE: 0x00E23068 (`CScriptObject` subobject at +0x10, 4 slots:
   *   `GetClass` 0x00648D70, `GetDerivedObjectRef` 0x00648D90, the destructor
   *   adjustor thunk 0x0064A120 -- `sub ecx, 0x10; jmp 0x649030` -- and
   *   0x004C70A0, inherited unchanged from `CScriptObject`)
   *
   * The layout is read straight off the default constructor at 0x00648FC0,
   * which after chaining to `IAniManipulator::IAniManipulator` writes both
   * vftables and then `mov [esi+0x80], 0`, nine `movss` zeroes covering
   * +0x84 through +0xA4, and `mov [esi+0xA8], 0`. `sizeof` is pinned
   * independently by `CStorageManipulatorTypeInfo::Init` (0x00648E10), whose
   * first store is `mov [esi+8], 0xB0`.
   *
   * The three vectors used to live behind a `CStorageManipulatorVector3RuntimeView`
   * stand-in -- three bare floats, converted to and from `Wm3::Vector3f` by a
   * pair of helpers on every use -- laid over the object together with a
   * `CStorageManipulatorRuntimeView` that carried the whole 0xB0 layout as
   * vtable words and padding. Both are gone: the binary addresses these fields
   * directly (`lea edx, [ebx+0x84]` straight into `WriteArchive::Write` at
   * 0x00649F7D, no temporary), which is only expressible once they are the
   * `Wm3::Vector3f` members they always were.
   */
  class CStorageManipulator : public IAniManipulator
  {
  public:
    /**
     * Address: 0x00648FC0 (FUN_00648FC0, ??0CStorageManipulator@Moho@@QAE@XZ)
     *
     * What it does:
     * Builds detached/default storage-manipulator state for the reflection
     * construction paths (`CStorageManipulatorTypeInfo::NewRef`/`CtrRef`):
     * no bound unit, all three offsets zeroed, resource defaulted to energy.
     */
    CStorageManipulator();

    /**
     * Address: 0x00649060 (FUN_00649060, ??0CStorageManipulator@Moho@@QAE@@Z)
     *
     * What it does:
     * Builds a storage manipulator bound to `unit`'s actor and sim, watching
     * `watchedBoneIndex`, interpolating between `maxOffset` (empty) and
     * `minOffset` (full) for `resourceType`, then creates its Lua object and
     * applies the initial offset to the watched bone.
     *
     * `mCur` starts at `maxOffset`, not at either extreme's midpoint: the
     * binary stores the same source vector into +0x84 and +0x9C
     * (0x006490BA/0x006490FF both read the `esi` argument).
     */
    CStorageManipulator(
      Unit* unit,
      int watchedBoneIndex,
      const Wm3::Vector3f& minOffset,
      const Wm3::Vector3f& maxOffset,
      EEconResource resourceType
    );

    /**
     * Address: 0x00649030 (FUN_00649030, `??_GCStorageManipulator@Moho@@UAEPAXI@Z`)
     *
     * VFTable SLOT: 0
     *
     * What it does:
     * `CStorageManipulator` owns no member that needs teardown, so the
     * slot-0 scalar deleting destructor is just `call 0x0062FC70`
     * (`~IAniManipulator`) followed by the conditional `::operator delete` --
     * exactly what a defaulted destructor produces.
     */
    ~CStorageManipulator() override = default;

    /**
     * Address: 0x00649260 (FUN_00649260, Moho::CStorageManipulator::MoveManipulator)
     *
     * VFTable SLOT: 1
     *
     * What it does:
     * Eases the current offset one tenth of the way toward the offset the
     * army's stored/max ratio for `mResourceType` calls for, then applies it
     * to the watched bone and signals the task event. A unit still under
     * construction holds its current offset instead of tracking storage.
     */
    bool ManipulatorUpdate() override;

    /**
     * Address: 0x00649DB0 (FUN_00649DB0, Moho::CStorageManipulator::MemberDeserialize)
     *
     * What it does:
     * Reads the `IAniManipulator` base payload, the owning unit as a tracked
     * pointer, `mMax`/`mMin`/`mCur` as `Wm3::Vector3f` values and
     * `mResourceType` as an `EEconResource`.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00649EF0 (FUN_00649EF0, Moho::CStorageManipulator::MemberSerialize)
     *
     * What it does:
     * Writes the same five payloads `MemberDeserialize` reads, the unit as an
     * unowned raw-pointer reference.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x006498C0 (FUN_006498C0)
     *
     * What it does:
     * Resolves and caches this class's reflected type descriptor, the global
     * the binary keeps at 0x010C73DC.
     *
     * The binary carries this body twice out of line, once here and once as
     * `GetClass` below -- the same pairing `IAniManipulator` has at
     * 0x0062FC10/0x0062FC30 and `CAimManipulator` at 0x0062FDF0/0x0062FE10.
     * Neither copy has a direct caller in the binary: the virtual is reached
     * through the vtable and every use of the static was inlined.
     */
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00648D70 (FUN_00648D70)
     *
     * VFTable SLOT: 0 (`CScriptObject` subobject at +0x10)
     *
     * What it does:
     * The same cached lookup as `StaticGetClass`, reached virtually. Leaving
     * it off the class left this slot resolving to `IAniManipulator`'s own
     * 0x0062FC30, which answers with the wrong reflected type.
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /// Cached reflected type descriptor -- the binary's 0x010C73DC.
    static gpg::RType* sType;

    /// The unit whose army economy drives the offset. Null on an instance
    /// built by the reflection construction paths, until deserialization
    /// binds one.
    Unit* mUnit;                 // +0x80
    /// The offset used when the tracked storage is empty.
    Wm3::Vector3f mMax;          // +0x84
    /// The offset used when the tracked storage is full.
    Wm3::Vector3f mMin;          // +0x90
    /// The offset actually applied this tick, eased toward the target.
    Wm3::Vector3f mCur;          // +0x9C
    EEconResource mResourceType; // +0xA8
    /// Never written by any constructor or method in the binary; it exists
    /// only because `CStorageManipulatorTypeInfo::Init` reports 0xB0 while the
    /// last named field ends at 0xAC.
    std::uint32_t mUnknown_0x0AC; // +0xAC
  };

  static_assert(offsetof(CStorageManipulator, mUnit) == 0x80, "CStorageManipulator::mUnit offset must be 0x80");
  static_assert(offsetof(CStorageManipulator, mMax) == 0x84, "CStorageManipulator::mMax offset must be 0x84");
  static_assert(offsetof(CStorageManipulator, mMin) == 0x90, "CStorageManipulator::mMin offset must be 0x90");
  static_assert(offsetof(CStorageManipulator, mCur) == 0x9C, "CStorageManipulator::mCur offset must be 0x9C");
  static_assert(
    offsetof(CStorageManipulator, mResourceType) == 0xA8,
    "CStorageManipulator::mResourceType offset must be 0xA8"
  );
  static_assert(sizeof(CStorageManipulator) == 0xB0, "CStorageManipulator size must be 0xB0");
} // namespace moho
