#include "moho/unit/tasks/CUnitRepairTask.h"

#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/Unit.h"

namespace moho
{
  /**
   * Address: 0x005F8C80 (??0CUnitRepairTask@Moho@@QAE@@Z)
   *
   * What it does:
   * Builds the repair-task command/listener subobjects, initializes the shared
   * build helper, binds the target weak lane, and primes the repair mode flags.
   */
  CUnitRepairTask::CUnitRepairTask(IAiCommandDispatchImpl* const dispatchTask, Unit* const targetUnit, const bool isSiloBuild)
    : CCommandTask(static_cast<CCommandTask*>(dispatchTask))
    , Listener<ECommandEvent>()
    , mBuildHelper("Repair", mUnit)
    , mCommand(nullptr)
    , mTargetUnit{}
    , mBuildTargetUnit{}
    , mInPosition(false)
    , mIsSilo(isSiloBuild)
    , mGuardAssistMode(false)
    , mInheritingWork(false)
  {
    mListenerLink.ListResetLinks();

    if (dispatchTask != nullptr && dispatchTask->mUnit != nullptr && dispatchTask->mUnit->CommandQueue != nullptr) {
      mCommand = dispatchTask->mUnit->CommandQueue->GetCurrentCommand();
      if (mCommand != nullptr) {
        mListenerLink.ListLinkBefore(static_cast<Broadcaster*>(mCommand));
      }
    }

    mTargetUnit.ResetFromObject(targetUnit);
    mBuildTargetUnit.ClearLinkState();

    if (mUnit != nullptr) {
      if (Unit* const target = mTargetUnit.GetObjectPtr(); target != nullptr && target->IsUnitState(UNITSTATE_Enhancing)) {
        mUnit->RunScriptWeakUnit("InheritWork", mTargetUnit);
        mInheritingWork = true;
      }
    }

    mGuardAssistMode = mUnit != nullptr
      && (mUnit->IsUnitState(UNITSTATE_Guarding) || mUnit->IsUnitState(UNITSTATE_AssistingCommander));
  }
} // namespace moho
