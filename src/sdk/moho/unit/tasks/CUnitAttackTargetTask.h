#pragma once

#include <cstddef>

#include "Wm3Vector3.h"
#include "moho/ai/EAiAttackerEvent.h"

namespace moho
{
  class CAiFormationInstance;
  class CAiTarget;
  class CCommandTask;
  struct SOCellPos;
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

    /**
     * Address: 0x005F2750 (FUN_005F2750, Moho::CAttackTargetTask::operator new `_0` overload)
     * Mangled: ??2CAttackTargetTask@Moho@@QAE@@Z_0
     *
     * What it does:
     * Formation-respecting attack task allocation overload. Like `Create`,
     * dispatches melee units through `CUnitMeleeAttackTargetTask`, otherwise
     * constructs a `CUnitAttackTargetTask` with `ignoreFormation=false` and a
     * caller-supplied overcharge-weapon toggle. Used when the dispatch lane
     * still has a live formation instance to honor.
     */
    [[nodiscard]] static CAttackTargetTask* CreateRespectFormation(
      CCommandTask* dispatchTask,
      CAiTarget* target,
      CAiFormationInstance* formation,
      bool enableOverchargeWeapon
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

    /**
     * Address: 0x005F2D90 (FUN_005F2D90, Moho::CUnitAttackTargetTask::SetPosGoal)
     *
     * What it does:
     * Builds one single-cell navigation goal from `targetCell` and submits it
     * through the owner unit navigator when present.
     */
    void SetPosGoal(const SOCellPos& targetCell);

    /**
     * Address: 0x005F2E90 (FUN_005F2E90, Moho::CUnitAttackTargetTask::UpdatePos)
     *
     * What it does:
     * Refreshes cached attack-target world position from current `mTarget`,
     * then falls back to owner-unit position when the cached vector is invalid.
     */
    void UpdatePos();

  private:
    /**
     * Address: 0x005F3EE0 (FUN_005F3EE0, Moho::Listener_AiAttackerEvent_CUnitAttackTargetTask::Receive)
     *
     * What it does:
     * Handles attacker-event state transitions for the ranged attack task,
     * updates dispatch-result lanes, and wakes the owner thread for immediate
     * re-evaluation.
     */
    void HandleAiAttackerEvent(EAiAttackerEvent event);

    /**
     * Address: 0x005F3450 (FUN_005F3450, Moho::CUnitAttackTargetTask::UpdateAttacker)
     *
     * What it does:
     * Updates owner attacker desired-target payload and relinks this task into
     * the attacker event-list lane when the entity target changed.
     */
    [[nodiscard]] bool UpdateAttacker(CAiTarget* desiredTarget);
  };

  static_assert(sizeof(CUnitAttackTargetTask) == 0x90, "CUnitAttackTargetTask size must be 0x90");
} // namespace moho
