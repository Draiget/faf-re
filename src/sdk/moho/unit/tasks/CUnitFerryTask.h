#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/WeakPtr.h"
#include "moho/task/CCommandTask.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class RRef;
  class RType;
}

namespace moho
{
  class IAiCommandDispatchImpl;
  class Unit;

  /**
   * Runtime owner for ferry task command lanes.
   */
  class CUnitFerryTask : public CCommandTask
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x0060E2C0 (FUN_0060E2C0, Moho::CUnitFerryTask::~CUnitFerryTask)
     *
     * What it does:
     * Aborts active navigation for the owner unit, clears ferry-task state bits,
     * and unlinks ferry/beacon weak-reference lanes before base-task teardown.
     */
    ~CUnitFerryTask() override;

    /**
     * Address: 0x0060DD70 (FUN_0060DD70, Moho::CUnitFerryTask::CUnitFerryTask)
     *
     * What it does:
     * Initializes one ferry task from dispatch + world-position context,
     * snapshots transport-load state, and binds current ferry-beacon command
     * ownership when present.
     */
    CUnitFerryTask(IAiCommandDispatchImpl* dispatch, const Wm3::Vector3f& ferryPosition);

    /**
     * Address: 0x0060DFC0 (FUN_0060DFC0, Moho::CUnitFerryTask::CUnitFerryTask)
     *
     * What it does:
     * Initializes one ferry-task lane from parent command-task and target-unit
     * payload context.
     */
    CUnitFerryTask(CCommandTask* parentTask, Unit* targetUnit);

    /**
     * Address: 0x0060F790 (FUN_0060F790, Moho::CUnitFerryTask::operator new)
     *
     * What it does:
     * Allocates one ferry-task object and forwards dispatch-position context
     * into in-place construction.
     */
    [[nodiscard]] static CUnitFerryTask* CreateFromDispatch(
      IAiCommandDispatchImpl* dispatch,
      const Wm3::Vector3f& ferryPosition
    );

    /**
     * Address: 0x0060F7E0 (FUN_0060F7E0, Moho::CUnitFerryTask::operator new)
     *
     * What it does:
     * Allocates one ferry-task object and forwards constructor arguments into
     * in-place construction.
     */
    [[nodiscard]] static CUnitFerryTask* Create(CCommandTask* parentTask, Unit* targetUnit);

  public:
    IAiCommandDispatchImpl* mDispatch; // 0x30
    std::int32_t mCommandIndex;        // 0x34
    bool mHasResolvedFerryTarget;      // 0x38
    std::uint8_t mPadding39[3];        // 0x39
    Wm3::Vector3f mPos;                // 0x3C
    WeakPtr<Unit> mCommandUnit;        // 0x48
    WeakPtr<Unit> mFerryUnit;          // 0x50
    WeakPtr<Unit> mBeacon;             // 0x58
  };

  static_assert(sizeof(CUnitFerryTask) == 0x60, "CUnitFerryTask size must be 0x60");
  static_assert(offsetof(CUnitFerryTask, mDispatch) == 0x30, "CUnitFerryTask::mDispatch offset must be 0x30");
  static_assert(
    offsetof(CUnitFerryTask, mCommandIndex) == 0x34,
    "CUnitFerryTask::mCommandIndex offset must be 0x34"
  );
  static_assert(
    offsetof(CUnitFerryTask, mHasResolvedFerryTarget) == 0x38,
    "CUnitFerryTask::mHasResolvedFerryTarget offset must be 0x38"
  );
  static_assert(offsetof(CUnitFerryTask, mPos) == 0x3C, "CUnitFerryTask::mPos offset must be 0x3C");
  static_assert(offsetof(CUnitFerryTask, mCommandUnit) == 0x48, "CUnitFerryTask::mCommandUnit offset must be 0x48");
  static_assert(offsetof(CUnitFerryTask, mFerryUnit) == 0x50, "CUnitFerryTask::mFerryUnit offset must be 0x50");
  static_assert(offsetof(CUnitFerryTask, mBeacon) == 0x58, "CUnitFerryTask::mBeacon offset must be 0x58");
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00610650 (FUN_00610650, gpg::RRef_CUnitFerryTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitFerryTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitFerryTask(gpg::RRef* outRef, moho::CUnitFerryTask* value);

  /**
   * Address: 0x006105B0 (FUN_006105B0)
   *
   * What it does:
   * Wrapper lane that materializes one temporary `RRef_CUnitFerryTask` and
   * copies object/type fields into the destination reference record.
   */
  gpg::RRef* AssignCUnitFerryTaskRef(gpg::RRef* outRef, moho::CUnitFerryTask* value);
} // namespace gpg
