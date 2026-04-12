#include "moho/unit/tasks/CUnitPodAssist.h"

#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/entity/EntityFastVectorReflection.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"

namespace moho
{
  /**
   * Address: 0x0061D3B0 (FUN_0061D3B0, ??0CUnitPodAssist@Moho@@QAE@@Z)
   */
  CUnitPodAssist::CUnitPodAssist(
    CCommandTask* const dispatchTask
  )
    : CCommandTask(dispatchTask)
    , mDispatchTask(dispatchTask)
    , mAssistTarget{}
  {
    if (mUnit != nullptr) {
      mUnit->UnitStateMask |= (1ull << UNITSTATE_AssistingCommander);
    }

    Unit* const creatorUnit = (mUnit != nullptr) ? mUnit->CreatorRef.ResolveObjectPtr<Unit>() : nullptr;
    mAssistTarget.ResetFromObject(creatorUnit);

    bool detachAssistTarget = true;
    Unit* const assistTarget = mAssistTarget.GetObjectPtr();
    if (assistTarget != nullptr) {
      detachAssistTarget = !assistTarget->IsInCategory("PODSTAGINGPLATFORM");
    }

    if (detachAssistTarget) {
      mAssistTarget.ResetFromObject(nullptr);
    }

    mTaskState = TASKSTATE_Waiting;
  }

  /**
   * Address: 0x0061D7D0 (FUN_0061D7D0, Moho::CUnitPodAssist::operator new)
   */
  CUnitPodAssist* CUnitPodAssist::Create(
    CCommandTask* const dispatchTask
  )
  {
    return new (std::nothrow) CUnitPodAssist(dispatchTask);
  }

  int CUnitPodAssist::Execute()
  {
    return 1;
  }

  /**
   * Address: 0x0061E970 (FUN_0061E970, Moho::CUnitPodAssist::MemberDeserialize)
   *
   * What it does:
   * Reads CCommandTask base via cached `CCommandTask` RType, then reads
   * `mDispatchTask` (raw owned ptr) and `mAssistTarget` (WeakPtr<Unit>)
   * from the archive.
   */
  void CUnitPodAssist::MemberDeserialize(
    gpg::ReadArchive* const archive
  )
  {
    if (CCommandTask::sType == nullptr) {
      CCommandTask::sType = gpg::LookupRType(typeid(CCommandTask));
    }
    const gpg::RRef baseRef{};
    archive->Read(CCommandTask::sType, this, baseRef);

    const gpg::RRef ptrRef{};
    archive->ReadPointer_CCommandTask(&mDispatchTask, &ptrRef);

    if (WeakPtr<Unit>::sType == nullptr) {
      WeakPtr<Unit>::sType = gpg::LookupRType(typeid(WeakPtr<Unit>));
    }
    const gpg::RRef weakRef{};
    archive->Read(WeakPtr<Unit>::sType, &mAssistTarget, weakRef);
  }

  /**
   * Address: 0x0061EA10 (FUN_0061EA10, Moho::CUnitPodAssist::MemberSerialize)
   *
   * What it does:
   * Writes CCommandTask base via cached RType, then writes `mDispatchTask`
   * as an UNOWNED raw pointer ref, then writes `mAssistTarget` weak ref.
   */
  void CUnitPodAssist::MemberSerialize(
    gpg::WriteArchive* const archive
  ) const
  {
    if (CCommandTask::sType == nullptr) {
      CCommandTask::sType = gpg::LookupRType(typeid(CCommandTask));
    }
    const gpg::RRef baseRef{};
    archive->Write(CCommandTask::sType, const_cast<CUnitPodAssist*>(this), baseRef);

    gpg::RRef ptrRef{};
    (void)gpg::RRef_CCommandTask(&ptrRef, mDispatchTask);
    gpg::WriteRawPointer(archive, ptrRef, gpg::TrackedPointerState::Unowned, baseRef);

    if (WeakPtr<Unit>::sType == nullptr) {
      WeakPtr<Unit>::sType = gpg::LookupRType(typeid(WeakPtr<Unit>));
    }
    const gpg::RRef weakRef{};
    archive->Write(WeakPtr<Unit>::sType, const_cast<WeakPtr<Unit>*>(&mAssistTarget), weakRef);
  }
} // namespace moho
