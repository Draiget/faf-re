#pragma once

#include <cstddef>

#include "moho/task/CCommandTask.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E202C0
   * COL: 0x00E789EC
   * Source hint: c:\work\rts\main\code\src\sim\AiUnitCommands.cpp
   *
   * Task representing a unit being built by a constructor.
   * Derives from CCommandTask; binary size is 0x30 (no extra fields).
   */
  class CUnitGetBuiltTask : public CCommandTask
  {
  public:
    /**
     * Address: 0x0060A4D0 (FUN_0060A4D0, Moho::CUnitGetBuiltTask::TaskTick)
     *
     * What it does:
     * Tracks build completion for the owner unit and completes when the unit is
     * mobile and attached to a parent transporter/entity.
     */
    int Execute() override;

    /**
     * Address: 0x0060A550 (FUN_0060A550, Moho::CUnitGetBuiltTask::CUnitGetBuiltTask)
     *
     * What it does:
     * Runs the base `CCommandTask` detached constructor lane and installs the
     * `CUnitGetBuiltTask` vftable.
     */
    CUnitGetBuiltTask();

    /**
     * Address: 0x0060A570 (FUN_0060A570, scalar deleting destructor thunk)
     *
     * What it does:
     * Runs `CCommandTask` teardown for the built-task lane; no extra fields
     * are owned here.
     */
    ~CUnitGetBuiltTask() override;
  };

  static_assert(sizeof(CUnitGetBuiltTask) == 0x30, "CUnitGetBuiltTask size must be 0x30");
} // namespace moho
