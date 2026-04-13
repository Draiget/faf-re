#pragma once

#include <cstddef>

namespace moho
{
  /**
   * Minimal recovered layout owner for `CUnitMeleeAttackTargetTask` type lanes.
   */
  class CUnitMeleeAttackTargetTask
  {
  public:
    /**
     * Address: 0x00615570 (FUN_00615570, Moho::CUnitMeleeAttackTargetTask::CUnitMeleeAttackTargetTask)
     *
     * What it does:
     * Constructs one melee-attack-target task instance in place.
     */
    CUnitMeleeAttackTargetTask();

  private:
    unsigned char mPadding[0x90];
  };

  static_assert(sizeof(CUnitMeleeAttackTargetTask) == 0x90, "CUnitMeleeAttackTargetTask size must be 0x90");
} // namespace moho

