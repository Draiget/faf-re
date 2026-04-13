#pragma once

#include <cstddef>

#include "Wm3Vector3.h"

namespace moho
{
  class CAiFormationInstance;
  class CAiTarget;
  class CCommandTask;
  class UnitWeapon;

  /**
   * Minimal recovered owner lane for attack-target task dispatch allocation.
   */
  class CAttackTargetTask
  {
  public:
    /**
     * Address: 0x005F27D0 (FUN_005F27D0, Moho::CAttackTargetTask::operator new)
     *
     * What it does:
     * Chooses melee-vs-ranged attack task allocation from dispatch unit state,
     * then forwards into the corresponding dispatch-bound constructor lane.
     */
    [[nodiscard]] static CAttackTargetTask* Create(
      CCommandTask* dispatchTask,
      CAiTarget* target,
      CAiFormationInstance* formation
    );

  protected:
    unsigned char mPadding[0x90];
  };

  static_assert(sizeof(CAttackTargetTask) == 0x90, "CAttackTargetTask size must be 0x90");

  /**
   * Minimal recovered layout owner for attack-target task lanes.
   *
   * This class remains layout-stubbed while behavior methods are recovered
   * incrementally from binary evidence.
   */
  class CUnitAttackTargetTask : public CAttackTargetTask
  {
  public:
    CUnitAttackTargetTask() = default;

    /**
     * Address: 0x005F2980 (FUN_005F2980, Moho::CUnitAttackTargetTask::CUnitAttackTargetTask)
     *
     * What it does:
     * Initializes one ranged attack-target task from dispatch context, target
     * payload, formation lane, and overcharge toggle state.
     */
    CUnitAttackTargetTask(
      CCommandTask* dispatchTask,
      CAiTarget* target,
      CAiFormationInstance* formation,
      bool ignoreFormation,
      bool enableOverchargeWeapon
    );

    /**
     * Address: 0x005F2CE0 (FUN_005F2CE0, Moho::CUnitAttackTargetTask::SetWeaponGoal)
     *
     * What it does:
     * Builds one rectangular navigator goal around `targetPosition` using
     * weapon max radius and dispatches it to the owner unit navigator.
     */
    void SetWeaponGoal(const Wm3::Vector3f& targetPosition, UnitWeapon* weapon);
  };

  static_assert(sizeof(CUnitAttackTargetTask) == 0x90, "CUnitAttackTargetTask size must be 0x90");
} // namespace moho
