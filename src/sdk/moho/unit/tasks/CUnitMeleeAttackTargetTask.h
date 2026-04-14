#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/EAiAttackerEvent.h"
#include "moho/unit/ECommandEvent.h"
#include "moho/unit/tasks/CUnitAttackTargetTask.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
}

namespace moho
{
  class Entity;
  class Unit;
  struct SOCellPos;

  /**
   * Minimal recovered layout owner for `CUnitMeleeAttackTargetTask` type lanes.
   */
  class CUnitMeleeAttackTargetTask : public CAttackTargetTask
  {
  public:
    static gpg::RType* sType;

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
     * Address: 0x00617580 (FUN_00617580, Moho::CUnitMeleeAttackTargetTask::~CUnitMeleeAttackTargetTask)
     *
     * What it does:
     * Clears melee-task focus/target weak lanes, unlinks listeners, resets unit
     * attacking state, and tears down the embedded command-task base slice.
     */
    ~CUnitMeleeAttackTargetTask();

    /**
     * Address: 0x006154B0 (FUN_006154B0, Moho::CUnitMeleeAttackTargetTask::operator new)
     *
     * What it does:
     * Allocates one melee attack-target task and forwards into the
     * dispatch-bound constructor lane with formation-ignore disabled.
     */
    [[nodiscard]] static CUnitMeleeAttackTargetTask* CreateRespectFormation(
      CCommandTask* dispatchTask,
      CAiTarget* target,
      CAiFormationInstance* formation
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

    /**
     * Address: 0x00616C70 (FUN_00616C70, Moho::CUnitMeleeAttackTargetTask::TaskTick)
     *
     * What it does:
     * Executes one melee attack-task state-machine tick and returns scheduler
     * result code for task-thread dispatch.
     */
    int TaskTick();

  private:
    /**
     * Address: 0x00616390 (FUN_00616390)
     *
     * What it does:
     * Selects one nearby enemy unit candidate for waiting-state melee engage
     * and writes whether the returned selection has immediate melee-space.
     */
    [[nodiscard]] Unit* SelectWaitingMeleeTarget(bool* outHasImmediateMeleeSpace);

    /**
     * Address: 0x00615B80 (FUN_00615B80, Moho::CUnitMeleeAttackTargetTask::InRange)
     *
     * What it does:
     * Returns whether owner unit is within melee guard-scan radius of current
     * target (or cached target position when no target exists).
     */
    [[nodiscard]] bool InRange();

    /**
     * Address: 0x00615C30 (FUN_00615C30)
     *
     * What it does:
     * Returns true when this task is formation-bound and the formation lead
     * unit currently has one desired attacker target.
     */
    [[nodiscard]] bool HasFormationLeadDesiredTarget();

    /**
     * Address: 0x00615FB0 (FUN_00615FB0, Moho::CUnitMeleeAttackTargetTask::FreeSpot)
     *
     * What it does:
     * Releases planted O-grid reservation and aborts active navigator move.
     */
    void FreeSpot();

    /**
     * Address: 0x00616020 (FUN_00616020)
     *
     * What it does:
     * Returns true when the current destination cell still contacts the target
     * footprint/collision shell for melee engagement.
     */
    [[nodiscard]] bool IsDestinationCellInMeleeContactRange();

    /**
     * Address: 0x00615980 (FUN_00615980)
     *
     * What it does:
     * Builds one-cell navigator goal bounds from `destinationCell`, pushes the
     * goal to the owner navigator, and caches the destination cell lane.
     */
    void SetDestinationCellGoal(const SOCellPos& destinationCell);

    /**
     * Address: 0x00615920 (FUN_00615920)
     *
     * What it does:
     * Rebuilds one-cell navigator goal bounds from cached `mDestination`
     * without modifying task destination state.
     */
    void RefreshDestinationCellGoal();

    /**
     * Address: 0x006159F0 (FUN_006159F0)
     *
     * What it does:
     * Converts one world-space destination to footprint-origin cell
     * coordinates, then routes through `SetDestinationCellGoal`.
     */
    void SetDestinationGoalFromWorldPosition(const Wm3::Vector3f& worldPosition);

    /**
     * Address: 0x00615A70 (FUN_00615A70, Moho::CUnitMeleeAttackTargetTask::SetDestUnit)
     *
     * What it does:
     * Sets navigator destination-unit follow lane and refreshes the cached
     * destination cell from target footprint-centered world position.
     */
    void SetDestUnit(Entity* destinationEntity);

    /**
     * Address: 0x00615EF0 (FUN_00615EF0, Moho::CUnitMeleeAttackTargetTask::UpdateTarget)
     *
     * What it does:
     * Refreshes melee destination from formation-adjusted target position when
     * in formation mode, otherwise from live entity target weak-link state.
     */
    void UpdateTarget();

    /**
     * Address: 0x00615B10 (FUN_00615B10, Moho::CUnitMeleeAttackTargetTask::UpdatePosition)
     *
     * What it does:
     * Refreshes cached target world position from current target payload and
     * falls back to owner unit position when result is invalid.
     */
    void UpdatePosition();

    /**
     * Address: 0x00615FE0 (FUN_00615FE0)
     *
     * What it does:
     * Applies a new desired attacker target when it differs by entity;
     * otherwise resets attacker reporting state.
     */
    [[nodiscard]] bool UpdateDesiredTarget(CAiTarget* desiredTarget);

    /**
     * Address: 0x00615CA0 (FUN_00615CA0)
     *
     * What it does:
     * Reconciles formation/target state and refreshes melee navigator goals
     * from either formation-adjusted cells or current cached target position.
     */
    void RefreshMeleeNavigationGoal();

    /**
     * Address: 0x006172C0 (FUN_006172C0, listener callback lane)
     *
     * What it does:
     * Handles attacker-event transitions for melee task state flow, including
     * target refresh/replant when new melee contact room opens around focus
     * target.
     */
    void HandleAiAttackerEvent(EAiAttackerEvent event);

    /**
     * Address: 0x00617510 (FUN_00617510, listener callback lane)
     *
     * What it does:
     * Syncs command-target payload on event `0` and advances the task from
     * waiting to starting state.
     */
    void HandleCommandEvent(ECommandEvent event);
  };

  static_assert(sizeof(CUnitMeleeAttackTargetTask) == 0x90, "CUnitMeleeAttackTargetTask size must be 0x90");

  /**
   * Serializer helper for `CUnitMeleeAttackTargetTask`.
   */
  class CUnitMeleeAttackTargetTaskSerializer
  {
  public:
    /**
     * Address: 0x006177B0 (FUN_006177B0)
     *
     * What it does:
     * Resolves melee-task RTTI and binds this helper's load/save callbacks
     * into the type descriptor.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;      // +0x04
    gpg::SerHelperBase* mHelperPrev;      // +0x08
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(CUnitMeleeAttackTargetTaskSerializer, mHelperNext) == 0x04,
    "CUnitMeleeAttackTargetTaskSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CUnitMeleeAttackTargetTaskSerializer, mHelperPrev) == 0x08,
    "CUnitMeleeAttackTargetTaskSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CUnitMeleeAttackTargetTaskSerializer, mDeserialize) == 0x0C,
    "CUnitMeleeAttackTargetTaskSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitMeleeAttackTargetTaskSerializer, mSerialize) == 0x10,
    "CUnitMeleeAttackTargetTaskSerializer::mSerialize offset must be 0x10"
  );
  static_assert(
    sizeof(CUnitMeleeAttackTargetTaskSerializer) == 0x14,
    "CUnitMeleeAttackTargetTaskSerializer size must be 0x14"
  );
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00617B50 (FUN_00617B50, gpg::RRef_CUnitMeleeAttackTargetTask)
   *
   * What it does:
   * Builds one typed reflection reference for
   * `moho::CUnitMeleeAttackTargetTask*`, preserving dynamic-derived ownership
   * and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitMeleeAttackTargetTask(gpg::RRef* outRef, moho::CUnitMeleeAttackTargetTask* value);
} // namespace gpg
