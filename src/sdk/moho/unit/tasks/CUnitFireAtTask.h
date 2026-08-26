#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiTarget.h"
#include "moho/task/CCommandTask.h"

namespace gpg
{
  class ReadArchive;
  class RRef;
  class RType;
  class WriteArchive;
}

namespace moho
{
  class IAiCommandDispatchImpl;
  class UnitWeapon;

  class CUnitFireAtTask : public CCommandTask
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x0060B800 (FUN_0060B800, ??1CUnitFireAtTask@Moho@@QAE@@Z)
     * Mangled: ??1CUnitFireAtTask@Moho@@QAE@@Z
     *
     * What it does:
     * Clears the owner-unit busy bit, unlinks the embedded fire-target weak
     * lane, and then lets the inherited command-task teardown continue.
     */
    ~CUnitFireAtTask() override;

    /**
     * Address: 0x0060B1B0 (FUN_0060B1B0, ??2CUnitFireAtTask@Moho@@QAE@@Z)
     *
     * What it does:
     * Allocates one fire-at task object and forwards constructor arguments into
     * in-place task construction.
     */
    [[nodiscard]] static CUnitFireAtTask* Create(
      IAiCommandDispatchImpl* dispatchTask,
      CAiTarget* target,
      std::int32_t isNuclear
    );

    /**
     * Address: 0x0060B260 (FUN_0060B260, ??0CUnitFireAtTask@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes one fire-at task from dispatch context and picks the first
     * matching manual-fire weapon lane for the requested nuke/non-nuke mode.
     */
    CUnitFireAtTask(CCommandTask* dispatchTask, CAiTarget* target, std::int32_t isNuclear);

    /**
     * Address: 0x0060B380 (FUN_0060B380, Moho::CUnitFireAtTask::TaskTick)
     *
     * IDA signature:
     * int __thiscall Moho::CUnitFireAtTask::TaskTick(Moho::CUnitFireAtTask *this);
     *
     * What it does:
     * Manual-fire state machine. Moves the unit into the chosen weapon's
     * firing band (backing off to 110% of the minimum range when too close),
     * loads a silo round if one is needed, fires once, and finishes when the
     * unit stops being busy. Reports the order rejected when the constructor
     * matched no enabled weapon.
     */
    int Execute() override;

    /**
     * Address: 0x0060D430 (FUN_0060D430, Moho::CUnitFireAtTask::MemberDeserialize)
     *
     * IDA signature:
     * void __usercall sub_60D430(Moho::CUnitFireAtTask *this@<ecx>, gpg::ReadArchive *archive@<eax>);
     *
     * What it does:
     * Loads fire-at-task state from an archive in binary lane order:
     *   1. base `CCommandTask` subobject (by reflected type).
     *   2. `IAiCommandDispatchImpl* mDispatch` at +0x30, read as a tracked
     *      `CCommandTask*` pointer (`IAiCommandDispatchImpl` derives from
     *      `CCommandTask`) via `ReadPointer_CCommandTask`.
     *   3. `CAiTarget mTarget` at +0x34 (by reflected type).
     *   4. `UnitWeapon* mWeapon` at +0x54, read as a tracked pointer via
     *      `ReadPointer_UnitWeapon`.
     *   5. `std::int32_t mIsNuclear` at +0x58, read through the `ESiloType`
     *      reflected type (matches its use as an `ESiloType` throughout
     *      `Execute()`/`CAiSiloBuildImpl` calls; same 4-byte wire shape).
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0060D510 (FUN_0060D510, Moho::CUnitFireAtTask::MemberSerialize)
     *
     * IDA signature:
     * void __usercall sub_60D510(Moho::CUnitFireAtTask *this@<eax>, gpg::WriteArchive *archive@<edi>);
     *
     * What it does:
     * Writes fire-at-task state to an archive in the same binary lane order
     * as `MemberDeserialize`: base `CCommandTask` subobject, `mDispatch` (as
     * an unowned tracked `CCommandTask*` pointer), `mTarget` (by reflected
     * type), `mWeapon` (as an unowned tracked pointer), then `mIsNuclear`
     * (through the `ESiloType` reflected type).
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

  public:
    IAiCommandDispatchImpl* mDispatch; // +0x30
    CAiTarget mTarget;                 // +0x34
    UnitWeapon* mWeapon;               // +0x54
    std::int32_t mIsNuclear;           // +0x58
  };

  static_assert(offsetof(CUnitFireAtTask, mDispatch) == 0x30, "CUnitFireAtTask::mDispatch offset must be 0x30");
  static_assert(offsetof(CUnitFireAtTask, mTarget) == 0x34, "CUnitFireAtTask::mTarget offset must be 0x34");
  static_assert(offsetof(CUnitFireAtTask, mWeapon) == 0x54, "CUnitFireAtTask::mWeapon offset must be 0x54");
  static_assert(
    offsetof(CUnitFireAtTask, mIsNuclear) == 0x58,
    "CUnitFireAtTask::mIsNuclear offset must be 0x58"
  );
  static_assert(sizeof(CUnitFireAtTask) == 0x5C, "CUnitFireAtTask size must be 0x5C");

  /**
   * VFTABLE: 0x00E20394 (`??_7CUnitFireAtTaskSerializer@Moho@@6B@`)
   *
   * Demangled: Moho::CUnitFireAtTaskSerializer
   *
   * Confirmed via RTTI (`dumps/rtti_dump_all.hpp`) as a genuinely distinct,
   * single-inheritance derived class of `gpg::SerSaveLoadHelper<CUnitFireAtTask>`
   * (`HierarchyAttribs: 0x0`, `mdisp=0`) -- not a bare template instantiation.
   * Same two-adjacent-vtable shape already established for
   * `CUnitTeleportTaskSerializer` (see CUnitCallTeleport.h) and for this
   * codebase's other `SerSaveLoadHelper<T>` instantiations: the base
   * subobject's own vtable write is elided in the ctor below since it is
   * immediately overwritten by this derived level's.
   *
   * Per-instantiation addresses (one compiler-emitted body per `T`; see
   * `gpg::SerSaveLoadHelper<T>`'s class-level comment in Reflection.h for the
   * template's general shape):
   *  - VFTABLE (own, most-derived): 0x00E20394
   *    (`??_7CUnitFireAtTaskSerializer@Moho@@6B@`)
   *  - VFTABLE (base `SerSaveLoadHelper<CUnitFireAtTask>`, adjacent; write
   *    elided): 0x00E2039C
   *    (`??_7?$SerSaveLoadHelper@VCUnitFireAtTask@Moho@@@gpg@@6B@`)
   *  - ctor / compiler dynamic-initializer (`register_CUnitFireAtTaskSerializer`):
   *    0x00BD06B0 (`__xc_a`-reachable; no dead zero-xref COMDAT duplicate found)
   *  - dtor / atexit target (ResetLinks()-shaped unlink-then-self-link body,
   *    no separately recovered mangled symbol): 0x00BF9CF0
   *  - Init(): 0x0060BC60 (shared vtable-slot-0 body for both vtables above;
   *    raw IDA decompile matches the template's generic `Init()` exactly)
   *  - Deserialize(): 0x0060B100 (tail-jmp thunk: `archive` in EAX,
   *    `objectPtr` in ECX, jumps directly into
   *    `CUnitFireAtTask::MemberDeserialize`'s custom-ABI body at 0x0060D430)
   *  - Serialize(): 0x0060B110 (`objectPtr` in EAX, `archive` in EDI,
   *    calls `CUnitFireAtTask::MemberSerialize` at 0x0060D510)
   */
  class CUnitFireAtTaskSerializer final : public gpg::SerSaveLoadHelper<CUnitFireAtTask>
  {
  };

  /**
   * Address: 0x00BD06B0 (FUN_00BD06B0, register_CUnitFireAtTaskSerializer)
   *
   * What it does:
   * Forces this translation unit's global `CUnitFireAtTaskSerializer`
   * instance to link into the reflection bootstrap sequence. The
   * ctor/vtable-install/atexit-dtor-registration sequence this address
   * decompiles to is MSVC's own compiler-generated dynamic initializer for
   * that global, not hand-written source -- see `gpg::SerSaveLoadHelper<T>`
   * in Reflection.h.
   */
  void register_CUnitFireAtTaskSerializer();
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x0060CE10 (FUN_0060CE10, gpg::RRef_CUnitFireAtTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitFireAtTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitFireAtTask(gpg::RRef* outRef, moho::CUnitFireAtTask* value);

  /**
   * Address: 0x0060C800 (FUN_0060C800)
   *
   * What it does:
   * Wrapper lane that materializes one temporary `RRef_CUnitFireAtTask` and
   * copies object/type fields into the destination reference record.
   */
  gpg::RRef* AssignCUnitFireAtTaskRef(gpg::RRef* outRef, moho::CUnitFireAtTask* value);
} // namespace gpg
