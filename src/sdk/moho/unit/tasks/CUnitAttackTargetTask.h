#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "Wm3Vector3.h"
#include "moho/ai/EAiAttackerEvent.h"
#include "moho/unit/ECommandEvent.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
}

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
    static gpg::RType* sType;

    /**
     * Address: 0x005F2850 (FUN_005F2850, Moho::CUnitAttackTargetTask::CUnitAttackTargetTask)
     *
     * What it does:
     * Initializes one detached ranged attack-target task with self-linked
     * listener nodes and default target/cache state.
     */
    CUnitAttackTargetTask();

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
     * Address: 0x005F4160 (FUN_005F4160, Moho::CUnitAttackTargetTask::~CUnitAttackTargetTask)
     *
     * What it does:
     * Clears attack-task unit/listener lanes, disables temporary weapon state,
     * and tears down the embedded command-task base slice.
     */
    ~CUnitAttackTargetTask();

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

    /**
     * Address: 0x005F34C0 (FUN_005F34C0, Moho::CUnitAttackTargetTask::TaskTick)
     *
     * What it does:
     * Advances one ranged attack-target task tick through preparation,
     * movement/range management, attack handoff, and final fire gating.
     */
    [[nodiscard]] int TaskTick();

    /**
     * Address: 0x005F4DC0 (FUN_005F4DC0, Moho::CUnitAttackTargetTask::MemberDeserialize)
     *
     * What it does:
     * Deserializes base command-task state, attack-task pointer lanes, target
     * payload, and boolean state flags.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005F4F00 (FUN_005F4F00, Moho::CUnitAttackTargetTask::MemberSerialize)
     *
     * What it does:
     * Serializes base command-task state, attack-task pointer lanes, target
     * payload, and boolean state flags.
     */
    void MemberSerialize(gpg::WriteArchive* archive);

  private:
    /**
     * Address: 0x005F3020 (FUN_005F3020, Moho::CUnitAttackTargetTask::Update)
     *
     * What it does:
     * Refreshes formation/target-driven navigation goals, updates current
     * attack position cache, and applies per-layer targeting movement.
     */
    void Update();

    /**
     * Address: 0x005F2DF0 (FUN_005F2DF0, CUnitAttackTargetTask::SetPosGoalFromWorldPosition helper)
     *
     * What it does:
     * Converts one world-space position to owner-footprint cell origin and
     * routes it through `SetPosGoal`.
     */
    void SetPosGoalFromWorldPosition(const Wm3::Vector3f& position);

    /**
     * Address: 0x005F2F00 (FUN_005F2F00, CUnitAttackTargetTask::IsWithinHorizontalDistance helper)
     *
     * What it does:
     * Returns true when horizontal distance from owner to target cache is
     * below `distance`.
     */
    [[nodiscard]] bool IsWithinHorizontalDistance(float distance) const;

    /**
     * Address: 0x005F2FB0 (FUN_005F2FB0, CUnitAttackTargetTask::HasFormationLeadDesiredTarget helper)
     *
     * What it does:
     * Returns true when formation-lead attacker already has one desired target
     * while this task is still honoring formation updates.
     */
    [[nodiscard]] bool HasFormationLeadDesiredTarget() const;

    /**
     * Address: 0x005F3370 (FUN_005F3370, CUnitAttackTargetTask::RefreshNavigationGoal helper)
     *
     * What it does:
     * Refreshes navigation destination from current target/formation context.
     */
    void RefreshNavigationGoal();

    /**
     * Address: 0x005F3420 (FUN_005F3420, CUnitAttackTargetTask::AbortNavigation helper)
     *
     * What it does:
     * Re-enables formation influence on navigator and aborts current move.
     */
    void AbortNavigation();

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
     * Address: 0x005F4000 (FUN_005F4000, Moho::Listener_CommandEvent_CUnitAttackTargetTask::Receive)
     *
     * What it does:
     * Synchronizes task target payload from current command-event context,
     * refreshes attacker desired-target state, and wakes owner-thread flow.
     */
    void HandleCommandEvent(ECommandEvent event);

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

namespace gpg
{
  /**
   * Address: 0x005F4C10 (FUN_005F4C10, gpg::RRef_CUnitAttackTargetTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitAttackTargetTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitAttackTargetTask(gpg::RRef* outRef, moho::CUnitAttackTargetTask* value);
} // namespace gpg
