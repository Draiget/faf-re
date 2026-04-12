#include "moho/unit/tasks/CFactoryBuildTask.h"

#include <new>

#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/CUnitCommand.h"

namespace moho
{
  /**
   * Address: 0x005F9F20 (FUN_005F9F20)
   * Mangled: ??0CFactoryBuildTask@Moho@@QAE@@Z_0
   *
   * What it does:
   * Initializes one dispatch-bound factory build task, linking blueprint,
   * rally point unit weak pointer, and originating command weak pointer.
   */
  CFactoryBuildTask::CFactoryBuildTask(
    CCommandTask* const dispatchTask,
    const RUnitBlueprint* const blueprint,
    CUnitCommand* const command,
    Unit* const rallyPointUnit
  )
    : CCommandTask(dispatchTask)
    , mDispatch(static_cast<IAiCommandDispatchImpl*>(dispatchTask))
    , mBlueprint(blueprint)
    , mBuildHelper("FactoryBuild", dispatchTask ? dispatchTask->mUnit : nullptr)
    , mRallyPointUnit{}
    , mBuildCount(0)
    , mHasCommand(false)
    , mPad89{}
    , mCommand{}
  {
    // Link rally point unit weak pointer into owner chain.
    mRallyPointUnit.BindObjectUnlinked(rallyPointUnit);
    if (rallyPointUnit != nullptr) {
      (void)mRallyPointUnit.LinkIntoOwnerChainHeadUnlinked();
    }

    // Link originating command weak pointer into owner chain.
    mCommand.BindObjectUnlinked(command);
    if (command != nullptr) {
      (void)mCommand.LinkIntoOwnerChainHeadUnlinked();
    }

    // If the command object exists (non-null, non-sentinel), mark that we have one.
    if (mCommand.GetObjectPtr() != nullptr) {
      mHasCommand = true;
    }
  }
} // namespace moho
