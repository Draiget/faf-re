#include "moho/unit/tasks/CUnitFormAndMoveTask.h"

#include <new>

#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiFormationInstance.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/Unit.h"

namespace
{
  struct CUnitCommandCommandEventLinkView
  {
    std::uint8_t pad_0000_0034[0x34];
    moho::Broadcaster mCommandEventListenerHead;
  };

  static_assert(
    offsetof(CUnitCommandCommandEventLinkView, mCommandEventListenerHead) == 0x34,
    "CUnitCommandCommandEventLinkView::mCommandEventListenerHead offset must be 0x34"
  );

  struct CAiFormationInstanceStatusListenerHeadView
  {
    std::uint8_t pad_0000_0008[0x08];
    moho::Broadcaster mFormationStatusListenerHead;
  };

  static_assert(
    offsetof(CAiFormationInstanceStatusListenerHeadView, mFormationStatusListenerHead) == 0x08,
    "CAiFormationInstanceStatusListenerHeadView::mFormationStatusListenerHead offset must be 0x08"
  );

  [[nodiscard]] moho::Broadcaster* CommandEventListenerHead(moho::CUnitCommand* const command) noexcept
  {
    if (!command) {
      return nullptr;
    }

    auto* const view = reinterpret_cast<CUnitCommandCommandEventLinkView*>(command);
    return &view->mCommandEventListenerHead;
  }

  [[nodiscard]] moho::Broadcaster* FormationStatusListenerHead(moho::CAiFormationInstance* const formation) noexcept
  {
    if (!formation) {
      return nullptr;
    }

    auto* const view = reinterpret_cast<CAiFormationInstanceStatusListenerHeadView*>(formation);
    return &view->mFormationStatusListenerHead;
  }

  [[nodiscard]] moho::Broadcaster* NavigatorListenerHead(moho::IAiNavigator* const navigator) noexcept
  {
    if (!navigator) {
      return nullptr;
    }

    return reinterpret_cast<moho::Broadcaster*>(&navigator->mListenerNode);
  }
} // namespace

namespace moho
{
  gpg::RType* CUnitFormAndMoveTask::sType = nullptr;

  /**
   * Address: 0x006191F0 (FUN_006191F0, ctor helper lane)
   *
   * What it does:
   * Initializes one detached form-move task with self-linked listener lanes.
   */
  CUnitFormAndMoveTask::CUnitFormAndMoveTask()
    : CCommandTask()
    , mUnknown0030(0)
    , mNavigatorListenerVftable(0)
    , mNavigatorListenerLink{}
    , mUnknown0040(0)
    , mFormationStatusListenerVftable(0)
    , mFormationStatusListenerLink{}
    , mUnknown0050(0)
    , mCommandEventListenerVftable(0)
    , mCommandEventListenerLink{}
    , mFormation(nullptr)
    , mFormationArrivalSatisfied(0)
    , mPad0065_0068{0, 0, 0}
  {}

  /**
   * Address: 0x00619A90 (FUN_00619A90, ??2CUnitFormAndMoveTask@Moho@@QAE@@Z)
   *
   * What it does:
   * Allocates one form-move task when formation and dispatch navigator lanes
   * are valid, then forwards into constructor logic.
   */
  CUnitFormAndMoveTask* CUnitFormAndMoveTask::Create(
    CAiFormationInstance* const formation,
    IAiCommandDispatchImpl* const dispatchTask
  )
  {
    if (!formation || !dispatchTask || !dispatchTask->mUnit || !dispatchTask->mUnit->AiNavigator) {
      return nullptr;
    }

    void* const storage = ::operator new(sizeof(CUnitFormAndMoveTask), std::nothrow);
    if (storage == nullptr) {
      return nullptr;
    }

    return new (storage) CUnitFormAndMoveTask(static_cast<CCommandTask*>(dispatchTask), formation);
  }

  /**
   * Address: 0x00619250 (FUN_00619250, ??0CUnitFormAndMoveTask@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes one form-move task from dispatch/formation context, seeds
   * the current formation-adjusted navigator goal, and links listener lanes.
   */
  CUnitFormAndMoveTask::CUnitFormAndMoveTask(
    CCommandTask* const dispatchTask,
    CAiFormationInstance* const formation
  )
    : CCommandTask(dispatchTask)
    , mUnknown0030(0)
    , mNavigatorListenerVftable(0)
    , mNavigatorListenerLink{}
    , mUnknown0040(0)
    , mFormationStatusListenerVftable(0)
    , mFormationStatusListenerLink{}
    , mUnknown0050(0)
    , mCommandEventListenerVftable(0)
    , mCommandEventListenerLink{}
    , mFormation(formation)
    , mFormationArrivalSatisfied(0)
    , mPad0065_0068{0, 0, 0}
  {
    if (!mUnit) {
      return;
    }

    mUnit->UnitStateMask |= 0x0000000000000004ull;

    if (CUnitCommandQueue* const queue = mUnit->CommandQueue; queue != nullptr) {
      if (CUnitCommand* const currentCommand = queue->GetCurrentCommand(); currentCommand != nullptr) {
        if (Broadcaster* const commandListenerHead = CommandEventListenerHead(currentCommand); commandListenerHead != nullptr) {
          mCommandEventListenerLink.ListLinkBefore(commandListenerHead);
        }
      }
    }

    if (Broadcaster* const formationListenerHead = FormationStatusListenerHead(mFormation); formationListenerHead != nullptr) {
      mFormationStatusListenerLink.ListLinkBefore(formationListenerHead);
    }

    ApplyFormationGoalFromCurrentUnit();
    mTaskState = TASKSTATE_Waiting;

    if (mUnit->IsUnitState(UNITSTATE_Immobile)) {
      if (const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();
          blueprint != nullptr && blueprint->AI.NeedUnpack && mUnit->AiAttacker != nullptr) {
        CAiTarget stopTarget{};
        stopTarget.targetPoint = -1;
        stopTarget.targetIsMobile = false;
        mUnit->AiAttacker->SetDesiredTarget(&stopTarget);
      }
    }

    mUnit->UpdateSpeedThroughStatus();

    if (IAiNavigator* const navigator = mUnit->AiNavigator; navigator != nullptr) {
      if (Broadcaster* const navigatorListenerHead = NavigatorListenerHead(navigator); navigatorListenerHead != nullptr) {
        mNavigatorListenerLink.ListLinkBefore(navigatorListenerHead);
      }
    }

    if (mOwnerThread != nullptr && !mOwnerThread->mStaged) {
      mOwnerThread->Stage();
    }
  }

  /**
   * Address: 0x006194E0 (FUN_006194E0, ??1CUnitFormAndMoveTask@Moho@@QAE@@Z)
   *
   * What it does:
   * Unlinks all listener lanes, aborts navigator movement, clears unit
   * form-move state bit, and tears down command-task ownership.
   */
  CUnitFormAndMoveTask::~CUnitFormAndMoveTask()
  {
    if (mUnit != nullptr) {
      mUnit->UnitStateMask &= ~0x0000000000000004ull;
    }

    if (mUnit != nullptr && mUnit->CommandQueue != nullptr && mUnit->CommandQueue->GetCurrentCommand() != nullptr) {
      mCommandEventListenerLink.ListUnlink();
    }

    if (mFormation != nullptr) {
      mFormationStatusListenerLink.ListUnlink();
    }

    if (mUnit != nullptr) {
      if (IAiNavigator* const navigator = mUnit->AiNavigator; navigator != nullptr) {
        mNavigatorListenerLink.ListUnlink();
        navigator->AbortMove();
      }
    }

    mCommandEventListenerLink.ListResetLinks();
    mFormationStatusListenerLink.ListResetLinks();
    mNavigatorListenerLink.ListResetLinks();
  }

  /**
   * Address: 0x00619650 (FUN_00619650, Moho::CUnitFormAndMoveTask::TaskTick)
   *
   * What it does:
   * Returns active-task status when formation lane is valid and the unit has
   * not yet consumed cached formation-speed data.
   */
  int CUnitFormAndMoveTask::Execute()
  {
    if (mFormationArrivalSatisfied != 0u || mFormation == nullptr || mUnit == nullptr || mUnit->mInfoCache.mHasFormationSpeedData) {
      return -1;
    }

    return 1;
  }

  /**
   * Address: 0x00619680 (FUN_00619680, listener callback lane)
   *
   * What it does:
   * Applies navigator event state transitions and resumes owner thread
   * processing.
   */
  void CUnitFormAndMoveTask::HandleNavigatorEvent(const EAiNavigatorEvent event)
  {
    if (event == AINAVEVENT_Failed || event == AINAVEVENT_Aborted) {
      mTaskState = TASKSTATE_Starting;
    } else if (event == AINAVEVENT_Succeeded) {
      mTaskState = TASKSTATE_Waiting;
    }

    ResumeOwnerThreadNow();
  }

  /**
   * Address: 0x006196F0 (FUN_006196F0, listener callback lane)
   *
   * What it does:
   * Re-applies current formation-adjusted navigator goal when command
   * dispatch payload changes.
   */
  void CUnitFormAndMoveTask::HandleCommandEvent(const ECommandEvent)
  {
    ApplyFormationGoalFromCurrentUnit();
  }

  /**
   * Address: 0x00619770 (FUN_00619770, listener callback lane)
   *
   * What it does:
   * Handles formation status transitions by refreshing current formation goal
   * or marking form-move completion when the unit reaches valid formation lane.
   */
  void CUnitFormAndMoveTask::HandleFormationStatusEvent(const EFormationdStatus status)
  {
    if (status == FORMATIONSTATUS_FormationUpdated) {
      ApplyFormationGoalFromCurrentUnit();
      return;
    }

    if (status != FORMATIONSTATUS_FormationAtGoal) {
      return;
    }

    if (mFormation == nullptr || mUnit == nullptr) {
      return;
    }

    if (!mFormation->Func21(mUnit)) {
      return;
    }

    mFormationArrivalSatisfied = 1u;
    ResumeOwnerThreadNow();
  }

  void CUnitFormAndMoveTask::ApplyFormationGoalFromCurrentUnit()
  {
    if (mFormation == nullptr || mUnit == nullptr) {
      return;
    }

    IAiNavigator* const navigator = mUnit->AiNavigator;
    if (navigator == nullptr) {
      return;
    }

    SOCellPos formationCell{};
    (void)mFormation->GetAdjustedFormationPosition(&formationCell, mUnit, nullptr);
    navigator->SetGoal(SNavGoal(formationCell));
  }

  void CUnitFormAndMoveTask::ResumeOwnerThreadNow()
  {
    if (mOwnerThread == nullptr) {
      return;
    }

    mOwnerThread->mPendingFrames = 0;
    if (mOwnerThread->mStaged) {
      mOwnerThread->Unstage();
    }
  }
} // namespace moho
