#include "moho/unit/tasks/CUnitRepairTask.h"

#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/Unit.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCBuildTaskHelperType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CBuildTaskHelper));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrUnitType()
  {
    gpg::RType* type = moho::WeakPtr<moho::Unit>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      moho::WeakPtr<moho::Unit>::sType = type;
    }
    return type;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005FED70 (FUN_005FED70, Moho::CUnitRepairTask::MemberDeserialize)
   *
   * What it does:
   * Deserializes repair-task runtime state in binary lane order: command-task
   * base, build-helper lane, command raw pointer, weak target lanes, then flags.
   */
  void CUnitRepairTask::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Read(CachedCCommandTaskType(), static_cast<CCommandTask*>(this), ownerRef);
    archive->Read(CachedCBuildTaskHelperType(), &mBuildHelper, ownerRef);
    archive->ReadPointer_CUnitCommand(&mCommand, &ownerRef);
    archive->Read(CachedWeakPtrUnitType(), &mTargetUnit, ownerRef);
    archive->Read(CachedWeakPtrUnitType(), &mBuildTargetUnit, ownerRef);
    archive->ReadBool(&mInPosition);
    archive->ReadBool(&mIsSilo);
    archive->ReadBool(&mGuardAssistMode);
    archive->ReadBool(&mInheritingWork);
  }

  /**
   * Address: 0x005FEEC0 (FUN_005FEEC0)
   *
   * What it does:
   * Serializes repair-task runtime state in binary lane order: command-task
   * base, build-helper lane, command raw pointer, target weak lanes, then flags.
   */
  void CUnitRepairTask::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Write(CachedCCommandTaskType(), static_cast<const CCommandTask*>(this), ownerRef);
    archive->Write(CachedCBuildTaskHelperType(), &mBuildHelper, ownerRef);

    gpg::RRef commandRef{};
    (void)gpg::RRef_CUnitCommand(&commandRef, mCommand);
    gpg::WriteRawPointer(archive, commandRef, gpg::TrackedPointerState::Unowned, ownerRef);

    archive->Write(CachedWeakPtrUnitType(), &mTargetUnit, ownerRef);
    archive->Write(CachedWeakPtrUnitType(), &mBuildTargetUnit, ownerRef);

    archive->WriteBool(mInPosition);
    archive->WriteBool(mIsSilo);
    archive->WriteBool(mGuardAssistMode);
    archive->WriteBool(mInheritingWork);
  }

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

  /**
   * Address: 0x005FD410 (FUN_005FD410)
   *
   * What it does:
   * Preserves one serializer-save thunk lane for `CUnitRepairTask`.
   */
  [[maybe_unused]] void CUnitRepairTaskMemberSerializeAdapterLaneA(
    const CUnitRepairTask* const task,
    gpg::WriteArchive* const archive
  )
  {
    task->MemberSerialize(archive);
  }

  /**
   * Address: 0x005FDC60 (FUN_005FDC60)
   *
   * What it does:
   * Alternate serializer-save thunk lane for `CUnitRepairTask`.
   */
  [[maybe_unused]] void CUnitRepairTaskMemberSerializeAdapterLaneB(
    const CUnitRepairTask* const task,
    gpg::WriteArchive* const archive
  )
  {
    task->MemberSerialize(archive);
  }
} // namespace moho
