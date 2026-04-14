#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/WeakPtr.h"
#include "moho/task/CCommandTask.h"
#include "Wm3Vector3.h"

namespace moho
{
  class CUnitCommand;
  class IAiCommandDispatchImpl;
  class Unit;

  /**
   * Runtime owner for ferry task command lanes.
   */
  class CUnitFerryTask : public CCommandTask
  {
  public:
    /**
     * Address: 0x0060E2C0 (FUN_0060E2C0, Moho::CUnitFerryTask::~CUnitFerryTask)
     *
     * What it does:
     * Aborts active navigation for the owner unit, clears ferry-task state bits,
     * and unlinks ferry/beacon weak-reference lanes before base-task teardown.
     */
    ~CUnitFerryTask() override;

    /**
     * Address: 0x0060DFC0 (FUN_0060DFC0, Moho::CUnitFerryTask::CUnitFerryTask)
     *
     * What it does:
     * Initializes one ferry-task lane from parent command-task and command
     * payload context.
     */
    CUnitFerryTask(CCommandTask* parentTask, CUnitCommand* command);

    /**
     * Address: 0x0060F7E0 (FUN_0060F7E0, Moho::CUnitFerryTask::operator new)
     *
     * What it does:
     * Allocates one ferry-task object and forwards constructor arguments into
     * in-place construction.
     */
    [[nodiscard]] static CUnitFerryTask* Create(CCommandTask* parentTask, CUnitCommand* command);

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
