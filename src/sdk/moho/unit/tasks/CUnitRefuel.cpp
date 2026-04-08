#include "moho/unit/tasks/CUnitRefuel.h"

#include <limits>

#include "moho/ai/IAiTransport.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"

namespace moho
{
  /**
   * Address: 0x00620F50 (FUN_00620F50, ??0CUnitRefuel@Moho@@QAE@@Z)
   */
  CUnitRefuel::CUnitRefuel(Unit* const targetUnit, IAiCommandDispatchImpl* const dispatchTask)
    : CCommandTask(static_cast<CCommandTask*>(dispatchTask))
    , mTargetUnit{}
    , mHasTransportReservation(false)
    , mIsCarrier(false)
    , mPad3A{}
  {
    mTargetUnit.ResetFromObject(targetUnit);

    if (mUnit != nullptr) {
      mUnit->UnitStateMask |= (1ull << UNITSTATE_Refueling);
      mUnit->UpdateSpeedThroughStatus();
    }

    Unit* const linkedTarget = mTargetUnit.GetObjectPtr();
    mIsCarrier = (linkedTarget != nullptr) && linkedTarget->IsInCategory("CARRIER");

    if (mUnit != nullptr && mUnit->AiNavigator != nullptr) {
      mUnit->AiNavigator->IgnoreFormation(true);
    }
  }

  /**
   * Address: 0x00621060 (FUN_00621060, ??1CUnitRefuel@Moho@@QAE@@Z)
   */
  CUnitRefuel::~CUnitRefuel()
  {
    mUnit->UnitStateMask &= ~(1ull << UNITSTATE_ForceSpeedThrough);
    mUnit->UnitStateMask &= ~(1ull << UNITSTATE_Refueling);
    mUnit->UpdateSpeedThroughStatus();

    if (mUnit->AiNavigator != nullptr) {
      mUnit->AiNavigator->IgnoreFormation(false);
    }

    Unit* const targetUnit = mTargetUnit.GetObjectPtr();
    if (mHasTransportReservation) {
      if (mUnit->UnitMotion != nullptr) {
        mUnit->UnitMotion->mHeight = std::numeric_limits<float>::infinity();
      }

      if (targetUnit != nullptr && !targetUnit->IsDead() && !mIsCarrier) {
        targetUnit->AiTransport->TransportRemovePickupUnit(mUnit, true);
      }
    }

    bool targetIsCarrier = false;
    if (targetUnit != nullptr && !targetUnit->IsDead()) {
      targetIsCarrier = targetUnit->IsInCategory("CARRIER");
    }

    if (targetIsCarrier) {
      targetUnit->AiTransport->TransportResetReservation();
    }

    *mDispatchResult = static_cast<EAiResult>(1);
    mTargetUnit.UnlinkFromOwnerChain();
  }

  int CUnitRefuel::Execute()
  {
    return -1;
  }
} // namespace moho
