#include "moho/unit/tasks/CFactoryBuildTask.h"

#include <typeinfo>
#include <new>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
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

  [[nodiscard]] gpg::RType* ResolveCBuildTaskHelperType()
  {
    static gpg::RType* type = nullptr;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::CBuildTaskHelper));
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveWeakPtrUnitType()
  {
    gpg::RType* type = moho::WeakPtr<moho::Unit>::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      moho::WeakPtr<moho::Unit>::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveWeakPtrCUnitCommandType()
  {
    gpg::RType* type = moho::WeakPtr<moho::CUnitCommand>::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::CUnitCommand>));
      moho::WeakPtr<moho::CUnitCommand>::sType = type;
    }
    return type;
  }

  constexpr std::uint64_t kUnitStateBuildingMask = (1ull << static_cast<std::uint32_t>(moho::UNITSTATE_Building));
  constexpr std::uint64_t kUnitStateBusyMask = (1ull << static_cast<std::uint32_t>(moho::UNITSTATE_Busy));

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

  /**
   * Address: 0x005FA010 (FUN_005FA010, Moho::CFactoryBuildTask::~CFactoryBuildTask)
   * Thunk entry: 0x005FA110 (FUN_005FA110, scalar deleting destructor thunk)
   *
   * What it does:
   * Clears owner build/busy unit-state bits, resets work progress, dispatches
   * build stop + result lanes, and unlinks both weak-pointer member lanes.
   */
  CFactoryBuildTask::~CFactoryBuildTask()
  {
    mUnit->UnitStateMask &= ~(kUnitStateBuildingMask | kUnitStateBusyMask);
    mUnit->WorkProgress = 0.0f;

    if (mTaskState == TASKSTATE_Complete) {
      mBuildHelper.OnStopBuild(true);
      *mDispatchResult = static_cast<EAiResult>(1);
    } else {
      mBuildHelper.OnStopBuild(false);
      *mDispatchResult = static_cast<EAiResult>(2);
    }

    mCommand.UnlinkFromOwnerChain();
    mRallyPointUnit.UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x005FF020 (FUN_005FF020, Moho::CFactoryBuildTask::MemberDeserialize)
   *
   * What it does:
   * Deserializes factory-build task state in binary lane order: base command
   * task, dispatch pointer lane, blueprint pointer lane, build helper lane,
   * rally weak lane, build count, command-present flag, then command weak lane.
   */
  void CFactoryBuildTask::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Read(ResolveCCommandTaskType(), static_cast<CCommandTask*>(this), ownerRef);

    CCommandTask* dispatchTask = nullptr;
    archive->ReadPointer_CCommandTask(&dispatchTask, &ownerRef);
    mDispatch = static_cast<IAiCommandDispatchImpl*>(dispatchTask);

    RUnitBlueprint* blueprint = nullptr;
    archive->ReadPointer_RUnitBlueprint(&blueprint, &ownerRef);
    mBlueprint = blueprint;

    archive->Read(ResolveCBuildTaskHelperType(), &mBuildHelper, ownerRef);
    archive->Read(ResolveWeakPtrUnitType(), &mRallyPointUnit, ownerRef);
    archive->ReadInt(&mBuildCount);
    archive->ReadBool(&mHasCommand);
    archive->Read(ResolveWeakPtrCUnitCommandType(), &mCommand, ownerRef);
  }

  /**
   * Address: 0x005FF160 (FUN_005FF160, Moho::CFactoryBuildTask::MemberSerialize)
   *
   * What it does:
   * Serializes factory-build task state in binary lane order: base command
   * task, dispatch pointer lane, blueprint pointer lane, build helper lane,
   * rally weak lane, build count, command-present flag, then command weak lane.
   */
  void CFactoryBuildTask::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Write(ResolveCCommandTaskType(), static_cast<const CCommandTask*>(this), ownerRef);

    gpg::RRef dispatchRef{};
    (void)gpg::RRef_CCommandTask(&dispatchRef, static_cast<CCommandTask*>(mDispatch));
    gpg::WriteRawPointer(archive, dispatchRef, gpg::TrackedPointerState::Unowned, ownerRef);

    gpg::RRef blueprintRef{};
    (void)gpg::RRef_RUnitBlueprint(&blueprintRef, const_cast<RUnitBlueprint*>(mBlueprint));
    gpg::WriteRawPointer(archive, blueprintRef, gpg::TrackedPointerState::Unowned, ownerRef);

    archive->Write(ResolveCBuildTaskHelperType(), &mBuildHelper, ownerRef);
    archive->Write(ResolveWeakPtrUnitType(), &mRallyPointUnit, ownerRef);
    archive->WriteInt(mBuildCount);
    archive->WriteBool(mHasCommand);
    archive->Write(ResolveWeakPtrCUnitCommandType(), &mCommand, ownerRef);
  }

  /**
   * Address: 0x005FD490 (FUN_005FD490)
   *
   * What it does:
   * Preserves one serializer-save thunk lane for `CFactoryBuildTask`.
   */
  [[maybe_unused]] void CFactoryBuildTaskMemberSerializeAdapterLaneA(
    const CFactoryBuildTask* const task,
    gpg::WriteArchive* const archive
  )
  {
    task->MemberSerialize(archive);
  }

  /**
   * Address: 0x005FDC80 (FUN_005FDC80)
   *
   * What it does:
   * Alternate serializer-save thunk lane for `CFactoryBuildTask`.
   */
  [[maybe_unused]] void CFactoryBuildTaskMemberSerializeAdapterLaneB(
    const CFactoryBuildTask* const task,
    gpg::WriteArchive* const archive
  )
  {
    task->MemberSerialize(archive);
  }
} // namespace moho
