#include "moho/unit/tasks/CUnitGuardTask.h"

#include "moho/ai/CAiAttackerImpl.h"
#include "moho/entity/Entity.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/unit/core/Unit.h"

namespace moho
{
  /**
   * Address: 0x006110F0 (FUN_006110F0, Moho::CUnitGuardTask::CUnitGuardTask)
   *
   * What it does:
   * Initializes guard-task command/listener lanes, clears weak references,
   * resets target payload, and zeros guard-goal rectangle state.
   */
  CUnitGuardTask::CUnitGuardTask()
    : CCommandTask()
    , mUnknown0030(0)
    , mCommandEventListenerVftable(0)
    , mCommandEventListenerLink{}
    , mCommandTask(nullptr)
    , mPrimaryUnit{}
    , mCommandRef{}
    , mTarget{}
    , mTrackGuardedUnit(false)
    , mRefreshGuardedUnitFromNearby(false)
    , mDisableBestEnemySearch(false)
    , mDisableReactionState(false)
    , mPreferTransportRefuel(false)
    , mAllowFerryBeaconRedirect(false)
    , mUnknown7A(false)
    , mPad007B(0)
    , mSecondaryUnit{}
    , mGuardDirection(Wm3::Vector3f::Zero())
    , mPad0090_009B{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
    , mGuardGoal{}
  {
    mTarget.targetType = EAiTargetType::AITARGET_None;
    mTarget.targetEntity.ClearLinkState();
    mTarget.position = Wm3::Vector3f::Zero();
    mTarget.targetPoint = -1;
    mTarget.targetIsMobile = false;

    mGuardGoal.minX = 0;
    mGuardGoal.minZ = 0;
    mGuardGoal.maxX = 0;
    mGuardGoal.maxZ = 0;
    mGuardGoal.aux0 = 0;
    mGuardGoal.aux1 = 0;
    mGuardGoal.aux2 = 0;
    mGuardGoal.aux3 = 0;
    mGuardGoal.mLayer = static_cast<ELayer>(0);
  }

  /**
   * Address: 0x00612AF0 (FUN_00612AF0, Moho::CUnitGuardTask::GetBestEnemy)
   *
   * What it does:
   * Uses the owner's attacker interface to pick the best enemy in guard-scan
   * range and clears any cached guard-move reservation direction when a new
   * enemy target is acquired.
   */
  Entity* CUnitGuardTask::GetBestEnemy()
  {
    Unit* const unit = mUnit;
    if (unit == nullptr || unit->AiAttacker == nullptr || mDisableBestEnemySearch || mDisableReactionState) {
      return nullptr;
    }

    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    const float guardScanRadius = (blueprint != nullptr) ? blueprint->AI.GuardScanRadius : 0.0f;

    CAiAttackerImpl* const attacker = unit->AiAttacker;
    UnitWeapon* const primaryWeapon = attacker->GetPrimaryWeapon();
    Entity* const bestEnemy = attacker->FindBestEnemy(primaryWeapon, &unit->mBlipsInRange, guardScanRadius, false);
    if (bestEnemy == nullptr) {
      return nullptr;
    }

    const Wm3::Vector3f zero = Wm3::Vector3f::Zero();
    if (Wm3::Vector3f::Compare(&mGuardDirection, &zero)) {
      mGuardDirection = zero;
      unit->FreeOgridRect();
    }
    return bestEnemy;
  }

  /**
   * Address: 0x006141A0 (FUN_006141A0, Moho::CUnitGuardTask::TaskTick)
   * Slot: 1
   *
   * What it does:
   * Advances guard-task behavior one tick: scans enemies around the guarded
   * unit and routes new targets through the owner's command queue. Body not
   * yet fully recovered; placeholder override satisfies the CTask contract
   * (matches the `return 1;` shape used by other recovered CCommandTask
   * slot-1 entries such as CAcquireTargetTask::Execute).
   */
  int CUnitGuardTask::Execute()
  {
    return 1;
  }
} // namespace moho
