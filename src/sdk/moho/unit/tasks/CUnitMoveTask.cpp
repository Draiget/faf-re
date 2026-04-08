#include "moho/unit/tasks/CUnitMoveTask.h"

#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitCallTransport.h"

namespace
{
  [[nodiscard]] moho::Unit* ResolveAssignedTransportUnit(moho::Unit* const unit) noexcept
  {
    if (!unit) {
      return nullptr;
    }

    return unit->AssignedTransportRef.ResolveObjectPtr<moho::Unit>();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00618A70 (FUN_00618A70, Moho::CUnitMoveTask::OnEvent)
   *
   * What it does:
   * Issues one transport-call command for the assigned ferry transport when
   * transport-category gating passes, then marks dispatch complete.
   */
  int CUnitMoveTask::OnEvent()
  {
    if (mTransportDispatchIssued != 0u) {
      return -1;
    }

    bool shouldIssueTransportCall = false;
    if (mRequiresTransportCategoryCheck != 0u) {
      Unit* const transportUnit = ResolveAssignedTransportUnit(mUnit);
      if (transportUnit != nullptr && transportUnit->IsInCategory("TRANSPORTATION")) {
        shouldIssueTransportCall = true;
      }
    }

    if (!shouldIssueTransportCall) {
      return -1;
    }

    if (mUnit->AiNavigator != nullptr) {
      mNavigatorListenerLink.mPrev->mNext = mNavigatorListenerLink.mNext;
      mNavigatorListenerLink.mNext->mPrev = mNavigatorListenerLink.mPrev;
      mNavigatorListenerLink.mNext = &mNavigatorListenerLink;
      mNavigatorListenerLink.mPrev = &mNavigatorListenerLink;
    }

    Unit* const transportUnit = ResolveAssignedTransportUnit(mUnit);
    NewCallTransportCommand(mDispatchTask, transportUnit);
    mTransportDispatchIssued = 1u;
    return 1;
  }
} // namespace moho
