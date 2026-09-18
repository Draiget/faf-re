#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "Wm3Vector3.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/EAiAttackerEvent.h"
#include "moho/misc/Listener.h"
#include "moho/task/CCommandTask.h"
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
   * Shared base for the two concrete attack-target tasks, and the home of the
   * dispatch allocation helpers.
   *
   * The RTTI carries no `CAttackTargetTask` type: both
   * `.?AVCUnitAttackTargetTask@Moho@@` and `.?AVCUnitMeleeAttackTargetTask@Moho@@`
   * list `Moho::CCommandTask` as their first base, followed by
   * `Listener<EAiAttackerEvent>` and `Listener<ECommandEvent>`. So this class is
   * a recovery-side holder for the two allocation lanes plus the layout the two
   * siblings share -- but it MUST carry the real `CCommandTask` base, because
   * that is where the task-thread's `Execute` vtable slot lives.
   *
   * Deriving from the raw-storage stub instead left the embedded command task
   * holding `CCommandTask`'s own vtable, so `CTaskStage::UserFrame` dispatched
   * every attack task into `CCommandTask::Execute` -- the `_purecall` slot,
   * whose recovered stand-in calls `std::terminate()`. Issuing any attack order
   * aborted the process from the sim thread.
   */
  /**
   * `Listener<EAiAttackerEvent>` (0x0C) plus the four-byte slot that separates
   * it from the `Listener<ECommandEvent>` base at +0x44. Both attack tasks lay
   * their attacker listener at +0x34 and their command listener at +0x44, which
   * leaves exactly one dword between the two 0x0C-byte bases.
   */
  class AiAttackerListenerWithSlot : public Listener<EAiAttackerEvent>
  {
  public:
    /// +0x40. Never read; present only to place the next base at +0x44.
    std::uint32_t mListenerPad{0};
  };

  static_assert(sizeof(AiAttackerListenerWithSlot) == 0x10, "AiAttackerListenerWithSlot size must be 0x10");

  class CAttackTargetTask
    : public CCommandTaskWithListenerSlot
    , public AiAttackerListenerWithSlot
    , public Listener<ECommandEvent>
  {
  public:
    using CCommandTaskWithListenerSlot::CCommandTaskWithListenerSlot;

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

  };

  // The base ends here, at +0x50: what used to be 0x40 bytes of padding is the
  // two siblings' own fields, and they now declare them.
  static_assert(sizeof(CAttackTargetTask) == 0x50, "CAttackTargetTask size must be 0x50");

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
     * VFTable SLOT: 1 (CTask::Execute)
     *
     * What it does:
     * Dispatches the command-task execute slot into `TaskTick`, the same way
     * `CUnitReclaimTask` and the other recovered command tasks do. The binary
     * puts `TaskTick` (0x005F34C0) straight in the slot; the forwarder keeps
     * `TaskTick` callable by name from the recovered helpers that already use
     * it.
     */
    int Execute() override;

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
    void MemberSerialize(gpg::WriteArchive* archive) const;

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
     * VFTable SLOT: 0 of `??_7CUnitAttackTargetTask@Moho@@6B?$Listener@W4EAiAttackerEvent@Moho@@@Moho@@@`,
     * installed at +0x34 by the constructor at 0x005F29E5.
     */
    void OnEvent(EAiAttackerEvent event) override { HandleAiAttackerEvent(event); }

    /**
     * VFTable SLOT: 0 of `??_7CUnitAttackTargetTask@Moho@@6B?$Listener@W4ECommandEvent@Moho@@@Moho@@@`,
     * installed at +0x44 by the constructor at 0x005F29EC.
     */
    void OnEvent(ECommandEvent event) override { HandleCommandEvent(event); }

    /**
     * Address: 0x005F3450 (FUN_005F3450, Moho::CUnitAttackTargetTask::UpdateAttacker)
     *
     * What it does:
     * Updates owner attacker desired-target payload and relinks this task into
     * the attacker event-list lane when the entity target changed.
     */
    [[nodiscard]] bool UpdateAttacker(CAiTarget* desiredTarget);
  public:
    // +0x00..+0x4F are the bases: `CCommandTaskWithListenerSlot`, the
    // attacker-event listener and the command-event listener.
    CCommandTask* mDispatchTask;      // +0x50
    CUnitCommand* mCommand;           // +0x54
    CAiFormationInstance* mFormation; // +0x58
    UnitWeapon* mWeapon;              // +0x5C
    CAiTarget mTarget;                // +0x60
    Wm3::Vector3f mTargetPosition;    // +0x80
    std::uint8_t mHasMobileTarget;    // +0x8C
    std::uint8_t mIgnoreFormationUpdates; // +0x8D
    std::uint8_t mIsGrounded;         // +0x8E
    std::uint8_t mPad008F;            // +0x8F
  };

  static_assert(
    offsetof(CUnitAttackTargetTask, mDispatchTask) == 0x50,
    "CUnitAttackTargetTask::mDispatchTask offset must be 0x50"
  );
  static_assert(
    offsetof(CUnitAttackTargetTask, mWeapon) == 0x5C, "CUnitAttackTargetTask::mWeapon offset must be 0x5C"
  );
  static_assert(
    offsetof(CUnitAttackTargetTask, mTarget) == 0x60, "CUnitAttackTargetTask::mTarget offset must be 0x60"
  );
  static_assert(
    offsetof(CUnitAttackTargetTask, mTargetPosition) == 0x80,
    "CUnitAttackTargetTask::mTargetPosition offset must be 0x80"
  );
  static_assert(
    offsetof(CUnitAttackTargetTask, mHasMobileTarget) == 0x8C,
    "CUnitAttackTargetTask::mHasMobileTarget offset must be 0x8C"
  );

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
