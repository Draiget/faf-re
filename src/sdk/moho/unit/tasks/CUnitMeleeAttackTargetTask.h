#pragma once

#include <cstddef>

#include "moho/unit/tasks/CUnitAttackTargetTask.h"

namespace moho
{
  /**
   * Minimal recovered layout owner for `CUnitMeleeAttackTargetTask` type lanes.
   */
  class CUnitMeleeAttackTargetTask : public CAttackTargetTask
  {
  public:
    /**
     * Address: 0x00615570 (FUN_00615570, Moho::CUnitMeleeAttackTargetTask::CUnitMeleeAttackTargetTask)
     *
     * What it does:
     * Constructs one melee-attack-target task instance in place.
     */
    CUnitMeleeAttackTargetTask();

    /**
     * Address: 0x00615690 (FUN_00615690, Moho::CUnitMeleeAttackTargetTask::CUnitMeleeAttackTargetTask)
     *
     * What it does:
     * Initializes one melee attack-target task from dispatch context, target
     * payload, formation lane, and formation-ignore mode.
     */
    CUnitMeleeAttackTargetTask(
      CCommandTask* dispatchTask,
      CAiTarget* target,
      CAiFormationInstance* formation,
      bool ignoreFormation
    );

    /**
     * Address: 0x00615510 (FUN_00615510, Moho::CUnitMeleeAttackTargetTask::operator new)
     *
     * What it does:
     * Allocates one melee attack-target task and forwards into dispatch-bound
     * constructor lane with formation-ignore enabled.
     */
    [[nodiscard]] static CUnitMeleeAttackTargetTask* Create(
      CCommandTask* dispatchTask,
      CAiTarget* target,
      CAiFormationInstance* formation
    );
  };

  static_assert(sizeof(CUnitMeleeAttackTargetTask) == 0x90, "CUnitMeleeAttackTargetTask size must be 0x90");
} // namespace moho
