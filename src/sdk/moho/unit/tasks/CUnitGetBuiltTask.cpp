#include "moho/unit/tasks/CUnitGetBuiltTask.h"

#include "gpg/core/utils/Global.h"
#include "moho/unit/core/Unit.h"

namespace moho
{
  namespace
  {
    constexpr const char* kAiUnitCommandsPath = "c:\\work\\rts\\main\\code\\src\\sim\\AiUnitCommands.cpp";
  }

  /**
   * Address: 0x0060A4D0 (FUN_0060A4D0, Moho::CUnitGetBuiltTask::TaskTick)
   *
   * What it does:
   * Tracks build completion for the owner unit and completes when the unit is
   * mobile and attached to a parent transporter/entity.
   */
  int CUnitGetBuiltTask::Execute()
  {
    if (mTaskState == TASKSTATE_Preparing) {
      if (mUnit->IsBeingBuilt()) {
        return 1;
      }

      if (!mUnit->IsMobile()) {
        return -1;
      }

      mTaskState = TASKSTATE_Waiting;
    } else if (mTaskState != TASKSTATE_Waiting) {
      gpg::HandleAssertFailure("Reached the supposably unreachable.", 557, kAiUnitCommandsPath);
    }

    return (mUnit->mAttachInfo.GetAttachTargetEntity() != nullptr) ? 1 : -1;
  }

  /**
   * Address: 0x0060A550 (FUN_0060A550, Moho::CUnitGetBuiltTask::CUnitGetBuiltTask)
   *
   * What it does:
   * Runs the detached `CCommandTask` base constructor and leaves the derived
   * task with its own vftable installed by the compiler.
   */
  CUnitGetBuiltTask::CUnitGetBuiltTask()
    : CCommandTask()
  {}

  /**
   * Address: 0x0060A570 (FUN_0060A570, scalar deleting destructor thunk)
   *
   * What it does:
   * Runs `CCommandTask` teardown for the built-task lane; there is no extra
   * derived state to release.
   */
  CUnitGetBuiltTask::~CUnitGetBuiltTask() = default;
} // namespace moho
