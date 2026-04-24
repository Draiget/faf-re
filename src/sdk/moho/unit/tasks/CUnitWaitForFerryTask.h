#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/WeakPtr.h"
#include "moho/path/SNavGoal.h"
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
  class Unit;

  /**
   * Runtime owner for wait-for-ferry task command lanes.
   */
  class CUnitWaitForFerryTask : public CCommandTask
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x0060FAA0 (FUN_0060FAA0, Moho::CUnitWaitForFerryTask::CUnitWaitForFerryTask)
     * Mangled: ??0CUnitWaitForFerryTask@Moho@@QAE@@Z
     *
     * What it does:
     * Initializes one wait-for-ferry task lane from dispatch context, stores
     * ferry weak-link ownership, copies navigation goal payload, and primes
     * unit focus/state for ferry assignment.
     */
    CUnitWaitForFerryTask(Unit* ferryUnit, IAiCommandDispatchImpl* dispatch, const SNavGoal& moveGoal);

    /**
     * Address: 0x0060FB90 (FUN_0060FB90, Moho::CUnitWaitForFerryTask::~CUnitWaitForFerryTask)
     * Mangled: ??1CUnitWaitForFerryTask@Moho@@QAE@@Z
     *
     * What it does:
     * Clears owner weak-link assignments for ferry/focus lanes, frees pending
     * occupancy-grid reservation, and drops the wait-for-ferry state bit.
     */
    ~CUnitWaitForFerryTask() override;

    /**
     * Address: 0x0060FF50 (FUN_0060FF50, Moho::CUnitWaitForFerryTask::operator new)
     * Mangled: ??2CUnitWaitForFerryTask@Moho@@QAE@@Z
     *
     * What it does:
     * Allocates one wait-for-ferry task object and forwards constructor
     * arguments into in-place construction.
     */
    [[nodiscard]] static CUnitWaitForFerryTask* Create(
      IAiCommandDispatchImpl* dispatch,
      const SNavGoal& moveGoal,
      Unit* ferryUnit
    );

    /**
     * Address: 0x00610D30 (FUN_00610D30, Moho::CUnitWaitForFerryTaskSerializer::Serialize body)
     *
     * IDA signature:
     * void __usercall sub_610D30(Moho::CUnitWaitForFerryTask *a1@<eax>, BinaryWriteArchive *a2@<edi>);
     *
     * What it does:
     * Writes wait-for-ferry task state to an archive in binary lane order:
     *   1. base `CCommandTask` subobject (by reflected type).
     *   2. raw `CCommandTask* mDispatch` as `unowned` tracked-pointer.
     *   3. `WeakPtr<Unit> mFerryUnit` slot (by reflected type).
     *   4. `SNavGoal mMoveGoal` slot (by reflected type).
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x00610C60 (FUN_00610C60, Moho::CUnitWaitForFerryTask::MemberDeserialize)
     *
     * IDA signature:
     * void __usercall sub_610C60(
     *   Moho::CCommandTask **obj@<ecx>, gpg::ReadArchive *a2@<eax>);
     *
     * What it does:
     * Loads wait-for-ferry task state from an archive in binary lane order:
     *   1. base `CCommandTask` subobject (by reflected type).
     *   2. raw `CCommandTask* mDispatch` as `unowned` tracked-pointer via
     *      `ReadArchive::ReadPointer_CCommandTask`.
     *   3. `WeakPtr<Unit> mFerryUnit` slot (by reflected type).
     *   4. `SNavGoal mMoveGoal` slot (by reflected type).
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

  public:
    IAiCommandDispatchImpl* mDispatch; // 0x30
    WeakPtr<Unit> mFerryUnit;          // 0x34
    SNavGoal mMoveGoal;                // 0x3C
  };

  static_assert(sizeof(CUnitWaitForFerryTask) == 0x60, "CUnitWaitForFerryTask size must be 0x60");
  static_assert(
    offsetof(CUnitWaitForFerryTask, mDispatch) == 0x30, "CUnitWaitForFerryTask::mDispatch offset must be 0x30"
  );
  static_assert(
    offsetof(CUnitWaitForFerryTask, mFerryUnit) == 0x34, "CUnitWaitForFerryTask::mFerryUnit offset must be 0x34"
  );
  static_assert(
    offsetof(CUnitWaitForFerryTask, mMoveGoal) == 0x3C, "CUnitWaitForFerryTask::mMoveGoal offset must be 0x3C"
  );
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00610800 (FUN_00610800, gpg::RRef_CUnitWaitForFerryTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitWaitForFerryTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitWaitForFerryTask(gpg::RRef* outRef, moho::CUnitWaitForFerryTask* value);

  /**
   * Address: 0x006105E0 (FUN_006105E0)
   *
   * What it does:
   * Wrapper lane that materializes one temporary
   * `RRef_CUnitWaitForFerryTask` and copies object/type fields into the
   * destination reference record.
   */
  gpg::RRef* AssignCUnitWaitForFerryTaskRef(gpg::RRef* outRef, moho::CUnitWaitForFerryTask* value);
} // namespace gpg
