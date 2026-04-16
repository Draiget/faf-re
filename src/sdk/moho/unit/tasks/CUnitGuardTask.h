#pragma once

#include <cstddef>
#include <cstdint>

#include "Wm3Vector3.h"
#include "moho/ai/CAiTarget.h"
#include "moho/misc/WeakPtr.h"
#include "moho/path/SNavGoal.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/Broadcaster.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
}

namespace moho
{
  class CUnitCommand;
  class Entity;
  struct RUnitBlueprint;
  struct SEntitySetTemplateUnit;
  struct SOCellPos;
  class Unit;

  /**
   * Recovered command-task owner for unit guard behavior state.
   */
  class CUnitGuardTask : public CCommandTask
  {
  public:
    /**
     * Address: 0x00614D50 (FUN_00614D50)
     *
     * What it does:
     * Deserializes guard-task runtime state, including command links, target
     * payload, guard-state flags, weak unit lanes, and movement goal vectors.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00614F80 (FUN_00614F80)
     *
     * What it does:
     * Serializes guard-task runtime state, including command links, target
     * payload, guard-state flags, weak unit lanes, and movement goal vectors.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x006110F0 (FUN_006110F0, Moho::CUnitGuardTask::CUnitGuardTask)
     *
     * What it does:
     * Initializes guard-task command/listener lanes, clears weak references,
     * resets target payload, and zeros guard-goal rectangle state.
     */
    CUnitGuardTask();

    /**
     * Address: 0x006141A0 (FUN_006141A0, Moho::CUnitGuardTask::TaskTick)
     * Slot: 1
     *
     * What it does:
     * Advances one guard-task tick: reconciles linked command ownership lanes,
     * refreshes guarded-unit state, dispatches follow-up guard subtasks
     * (refuel/ferry/build/combat/reclaim/assist), and updates move-goal
     * steering state.
     */
    int Execute() override;

  private:
    /**
     * Address: 0x00614170 (FUN_00614170, Moho::CUnitGuardTask::AbortMove)
     *
     * What it does:
     * Marks owner unit move-abort state flag and forwards one navigator abort
     * call when a navigator lane is present.
     */
    void AbortMove();

    /**
     * Address: 0x006147B0 (FUN_006147B0)
     *
     * What it does:
     * Handles command-listener refresh flow by copying the linked command
     * target payload into `mTarget` and refreshing guarded-unit lanes.
     */
    void OnLinkedCommandTargetChanged();

    /**
     * Address: 0x00611A40 (FUN_00611A40)
     *
     * What it does:
     * Refreshes guarded-unit weak lanes and guard position state from the
     * current `mTarget` payload, including transport/ferry preference flags.
     */
    void RefreshGuardedUnitFromTarget();

    /**
     * Address: 0x00611CD0 (FUN_00611CD0)
     *
     * What it does:
     * Walks the guarded-unit chain and chooses the unit that should source
     * guard-follow-up commands while avoiding previously visited units.
     */
    [[nodiscard]] Unit* ResolveGuardCommandSourceUnit(Unit* guardedUnit, SEntitySetTemplateUnit& visitedUnits) const;

    /**
     * Address: 0x00611DA0 (FUN_00611DA0)
     *
     * What it does:
     * Computes and reserves one guard move-anchor world position when the
     * cached move-anchor lane is still zero, then returns that lane.
     */
    [[nodiscard]] Wm3::Vector3f EnsureReservedGuardMoveAnchorPosition();

    /**
     * Address: 0x00611F30 (FUN_00611F30)
     *
     * What it does:
     * Resolves one rebuilder guard anchor from queued guard commands, caches
     * it into the secondary guard-anchor lane, and reserves owner ogrid space.
     */
    [[nodiscard]] Wm3::Vector3f ResolveRebuilderGuardQueueAnchorPosition();

    /**
     * Address: 0x00612220 (FUN_00612220)
     *
     * What it does:
     * Resolves the current guard reference world position from guarded-unit,
     * rebuilder queue, or queue-head command lanes.
     */
    [[nodiscard]] Wm3::Vector3f ResolveGuardReferencePosition();

    /**
     * Address: 0x00612480 (FUN_00612480)
     *
     * What it does:
     * Returns whether owner distance to the current guard reference position
     * exceeds guarded-footprint threshold plus `extraRange`.
     */
    [[nodiscard]] bool IsOutsideGuardReferenceRange(float extraRange);

    /**
     * Address: 0x00612560 (FUN_00612560)
     *
     * What it does:
     * Returns whether owner footprint-min cell lies inside one goal rectangle
     * bounds.
     */
    [[nodiscard]] bool IsOwnerCellInsideGoalBounds(const SNavGoal& goal) const;

    /**
     * Address: 0x00610E00 (FUN_00610E00)
     *
     * What it does:
     * Compares the primary goal rectangle bounds lanes (`min/max X/Z`) for
     * exact equality.
     */
    [[nodiscard]] static bool IsSameGoalBounds(const SNavGoal& lhs, const SNavGoal& rhs);

    /**
     * Address: 0x00613C40 (FUN_00613C40)
     *
     * What it does:
     * Updates guard-follow movement goal state, including move-target
     * preparation/clamping and navigator-goal submission gates.
     */
    void UpdateGuardFollowMoveGoal();

    /**
     * Address: 0x00612600 (FUN_00612600)
     *
     * What it does:
     * Evaluates engineer/pod guard completion gates using queue-next-command
     * and guarded-unit idle-state lanes.
     */
    [[nodiscard]] bool ShouldAbortGuardForBuilderContext() const;

    /**
     * Address: 0x006127F0 (FUN_006127F0)
     *
     * What it does:
     * Tries to dispatch factory-build/upgrade follow-up tasks from owner or
     * guarded-unit build queues for builder-guard lanes.
     */
    void TryDispatchFactoryOrUpgradeFromGuardQueues();

    /**
     * Address: 0x00612BB0 (FUN_00612BB0)
     *
     * What it does:
     * Resolves one guard-context structure blueprint and build-cell target from
     * rebuilder queues or guarded-unit build-mobile command lanes.
     */
    [[nodiscard]] const RUnitBlueprint* TryResolveGuardBuildBlueprint(SOCellPos& outBuildCellPos);

    /**
     * Address: 0x00613970 (FUN_00613970)
     *
     * What it does:
     * Converts one resolved build-cell target into world-space placement and
     * dispatches one mobile-build task for `buildBlueprint`.
     */
    void DispatchMobileBuildTask(const RUnitBlueprint* buildBlueprint, const SOCellPos& buildCellPos);

    /**
     * Address: 0x00612FB0 (FUN_00612FB0)
     *
     * What it does:
     * Returns whether owner builder queue already contains a guard command that
     * targets the candidate unit's current world position.
     */
    [[nodiscard]] bool HasGuardCommandAtUnitPosition(const Unit* candidateUnit) const;

    /**
     * Address: 0x00613110 (FUN_00613110)
     *
     * What it does:
     * Selects one assist/capture candidate unit from guarded focus lanes or
     * nearby guard-area scan lanes for follow-up dispatch.
     */
    [[nodiscard]] Unit* SelectAssistOrCaptureCandidateUnit();

    /**
     * Address: 0x00613A80 (FUN_00613A80)
     *
     * What it does:
     * Dispatches guard follow-up work for one candidate unit: allied targets
     * route to repair/silo-assist tasks, enemy targets route to capture.
     */
    void DispatchAssistOrCaptureTask(Unit* targetUnit);

    /**
     * Address: 0x006138F0 (FUN_006138F0, Moho::CUnitGuardTask::SetEnemy)
     *
     * What it does:
     * Builds one target payload for `enemy` and dispatches an attack-target
     * task bound to this guard task's command-dispatch lane.
     */
    void SetEnemy(Entity* enemy);

    /**
     * Address: 0x00613A10 (FUN_00613A10)
     *
     * What it does:
     * Builds one target payload for `targetEntity` and dispatches a reclaim
     * task through this guard task's command-dispatch lane.
     */
    void IssueReclaimTaskForEntity(Entity* targetEntity);

    /**
     * Address: 0x00612E80 (FUN_00612E80)
     *
     * What it does:
     * Returns the guarded unit's reclaim focus entity when this guard owner is
     * reclaim-capable and the guarded unit is actively reclaiming.
     */
    [[nodiscard]] Entity* ResolveGuardedReclaimFocusEntity() const;

    /**
     * Address: 0x00612AF0 (FUN_00612AF0, Moho::CUnitGuardTask::GetBestEnemy)
     *
     * What it does:
     * Uses the owner's attacker interface to pick the best enemy in guard-scan
     * range and clears any cached guard-move reservation direction when a new
     * enemy target is acquired.
     */
    [[nodiscard]] Entity* GetBestEnemy();

  public:
    std::uint32_t mUnknown0030; // +0x30
    std::uint32_t mCommandEventListenerVftable; // +0x34
    Broadcaster mCommandEventListenerLink; // +0x38
    CCommandTask* mCommandTask; // +0x40
    WeakPtr<CUnitCommand> mPrimaryCommandRef; // +0x44
    WeakPtr<CUnitCommand> mCommandRef; // +0x4C
    CAiTarget mTarget; // +0x54
    bool mTrackGuardedUnit; // +0x74 (v13a)
    bool mRefreshGuardedUnitFromNearby; // +0x75 (v13b)
    bool mDisableBestEnemySearch; // +0x76 (v13c)
    bool mDisableReactionState; // +0x77 (v13d)
    bool mPreferTransportRefuel; // +0x78 (v14a)
    bool mAllowFerryBeaconRedirect; // +0x79 (v14b)
    bool mUnknown7A; // +0x7A (v14c)
    std::uint8_t mPad007B; // +0x7B
    WeakPtr<Unit> mSecondaryUnit; // +0x7C
    Wm3::Vector3f mGuardDirection; // +0x84 (v17)
    Wm3::Vector3f mGuardMoveAnchorPosition; // +0x90 (v20)
    SNavGoal mGuardGoal; // +0x9C (v23)
  };

  static_assert(sizeof(CUnitGuardTask) == 0xC0, "CUnitGuardTask size must be 0xC0");
  static_assert(offsetof(CUnitGuardTask, mUnknown0030) == 0x30, "CUnitGuardTask::mUnknown0030 offset must be 0x30");
  static_assert(
    offsetof(CUnitGuardTask, mCommandEventListenerVftable) == 0x34,
    "CUnitGuardTask::mCommandEventListenerVftable offset must be 0x34"
  );
  static_assert(
    offsetof(CUnitGuardTask, mCommandEventListenerLink) == 0x38,
    "CUnitGuardTask::mCommandEventListenerLink offset must be 0x38"
  );
  static_assert(offsetof(CUnitGuardTask, mCommandTask) == 0x40, "CUnitGuardTask::mCommandTask offset must be 0x40");
  static_assert(
    offsetof(CUnitGuardTask, mPrimaryCommandRef) == 0x44,
    "CUnitGuardTask::mPrimaryCommandRef offset must be 0x44"
  );
  static_assert(offsetof(CUnitGuardTask, mCommandRef) == 0x4C, "CUnitGuardTask::mCommandRef offset must be 0x4C");
  static_assert(offsetof(CUnitGuardTask, mTarget) == 0x54, "CUnitGuardTask::mTarget offset must be 0x54");
  static_assert(
    offsetof(CUnitGuardTask, mTrackGuardedUnit) == 0x74,
    "CUnitGuardTask::mTrackGuardedUnit offset must be 0x74"
  );
  static_assert(
    offsetof(CUnitGuardTask, mRefreshGuardedUnitFromNearby) == 0x75,
    "CUnitGuardTask::mRefreshGuardedUnitFromNearby offset must be 0x75"
  );
  static_assert(
    offsetof(CUnitGuardTask, mDisableBestEnemySearch) == 0x76,
    "CUnitGuardTask::mDisableBestEnemySearch offset must be 0x76"
  );
  static_assert(
    offsetof(CUnitGuardTask, mDisableReactionState) == 0x77,
    "CUnitGuardTask::mDisableReactionState offset must be 0x77"
  );
  static_assert(
    offsetof(CUnitGuardTask, mPreferTransportRefuel) == 0x78,
    "CUnitGuardTask::mPreferTransportRefuel offset must be 0x78"
  );
  static_assert(
    offsetof(CUnitGuardTask, mAllowFerryBeaconRedirect) == 0x79,
    "CUnitGuardTask::mAllowFerryBeaconRedirect offset must be 0x79"
  );
  static_assert(offsetof(CUnitGuardTask, mUnknown7A) == 0x7A, "CUnitGuardTask::mUnknown7A offset must be 0x7A");
  static_assert(offsetof(CUnitGuardTask, mSecondaryUnit) == 0x7C, "CUnitGuardTask::mSecondaryUnit offset must be 0x7C");
  static_assert(
    offsetof(CUnitGuardTask, mGuardDirection) == 0x84,
    "CUnitGuardTask::mGuardDirection offset must be 0x84"
  );
  static_assert(
    offsetof(CUnitGuardTask, mGuardMoveAnchorPosition) == 0x90,
    "CUnitGuardTask::mGuardMoveAnchorPosition offset must be 0x90"
  );
  static_assert(offsetof(CUnitGuardTask, mGuardGoal) == 0x9C, "CUnitGuardTask::mGuardGoal offset must be 0x9C");
} // namespace moho
