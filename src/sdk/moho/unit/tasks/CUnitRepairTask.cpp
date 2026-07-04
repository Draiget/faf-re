#include "moho/unit/tasks/CUnitRepairTask.h"

#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/IAiBuilder.h"
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
   * Address: 0x005F8E20 (FUN_005F8E20, ??1CUnitRepairTask@Moho@@QAE@@Z body)
   * Scalar deleting dtor thunk: 0x005F8FE0 (FUN_005F8FE0, vtable slot 0)
   *
   * IDA signature:
   * int __stdcall Moho::CUnitRepairTask::~CUnitRepairTask(Moho::CUnitRepairTask *this);
   *
   * What it does:
   * Runs the "ClearWork" unit script, detaches the embedded command-event
   * listener, clears the owner unit's repairing state bit, zeros its work
   * progress and builder aim target, releases the reserved ogrid footprint
   * when still held mid-prep, clears the build-target unit's no-reclaim bit,
   * stops the shared build helper, records the task's dispatch result, and
   * unlinks the build-target/target weak lanes. The primary/Listener vftable
   * resets and the CBuildTaskHelper/CCommandTask sub-object teardowns are
   * emitted by the compiler and are not written here.
   */
  CUnitRepairTask::~CUnitRepairTask()
  {
    // Notify the unit script that the active repair work is being torn down.
    // The binary dereferences mUnit unconditionally here (no null guard).
    mUnit->RunScript("ClearWork");

    // Detach the embedded command-event listener from whatever broadcaster
    // ring it currently sits in and reset it to a self-linked singleton.
    mListenerLink.ListUnlinkSelf();

    // Drop the repairing state bit this task owns on the owner unit.
    mUnit->UnitStateMask &= ~(1ull << UNITSTATE_Repairing);

    // Clear the owner unit's cached work-progress and builder aim target.
    mUnit->WorkProgress = 0.0f;
    if (IAiBuilder* const builder = mUnit->AiBuilder; builder != nullptr) {
      builder->BuilderSetAimTarget(Wm3::Vector3f::Zero());
    }

    // Release the reserved ogrid footprint if we were still preparing and had
    // not yet reached the repair position (TASKSTATE_Waiting == 1).
    if (mTaskState == TASKSTATE_Waiting && !mInPosition) {
      mUnit->FreeOgridRect();
    }

    // Clear the no-reclaim protection bit on the unit we were building/assisting.
    if (Unit* const buildTarget = mBuildTargetUnit.GetObjectPtr(); buildTarget != nullptr) {
      buildTarget->UnitStateMask &= ~(1ull << UNITSTATE_NoReclaim);
    }

    // Stop the shared build helper (failed == true), matching the binary.
    mBuildHelper.OnStopBuild(true);

    // Publish the dispatch result: 1 when the task finished in TASKSTATE_5,
    // otherwise 2. EAiResult has no lexical labels in the recovered RTTI.
    *mDispatchResult = static_cast<EAiResult>(mTaskState == TASKSTATE_5 ? 1 : 2);

    // Unlink both weak lanes from their owner chains (declaration-reverse order
    // in the binary: build-target then target). WeakPtr<T>'s generic destructor
    // is trivial in our model, so these detaches are explicit.
    mBuildTargetUnit.UnlinkFromOwnerChain();
    mTargetUnit.UnlinkFromOwnerChain();

    // Final explicit Listener sub-object detach (trivially-destructible in our
    // model, so the compiler does not emit it): unlink and reset to singleton.
    mListenerLink.ListUnlinkSelf();
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
