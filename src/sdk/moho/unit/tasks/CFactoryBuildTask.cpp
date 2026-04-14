#include "moho/unit/tasks/CFactoryBuildTask.h"

#include <typeinfo>
#include <new>

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/CUnitCommand.h"

namespace
{
  [[nodiscard]] gpg::RType* ResolveCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x005FD420 (FUN_005FD420, func_RTypeAddBaseCCommandTask)
   *
   * What it does:
   * Resolves `CCommandTask` RTTI and registers it as a zero-offset reflection
   * base lane for task-derived type-info owners.
   */
  [[maybe_unused]] void AddBaseCCommandTask(gpg::RType* const typeInfo)
  {
    if (typeInfo == nullptr) {
      return;
    }

    gpg::RType* const baseType = ResolveCCommandTaskType();

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005F9EB0 (FUN_005F9EB0, Moho::CFactoryBuildTask::CFactoryBuildTask)
   *
   * What it does:
   * Initializes one detached factory-build task with empty dispatch, blueprint,
   * helper, rally-point, and command lanes.
   */
  CFactoryBuildTask::CFactoryBuildTask()
    : CCommandTask()
    , mDispatch(nullptr)
    , mBlueprint(nullptr)
    , mBuildHelper()
    , mRallyPointUnit{}
    , mBuildCount(0)
    , mHasCommand(false)
    , mPad89{}
    , mCommand{}
  {}

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
