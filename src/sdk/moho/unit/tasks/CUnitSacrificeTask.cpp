#include "moho/unit/tasks/CUnitSacrificeTask.h"

#include <cstddef>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/entity/Entity.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/Broadcaster.h"
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

  [[nodiscard]] gpg::RType* CachedWeakPtrUnitType()
  {
    gpg::RType* type = moho::WeakPtr<moho::Unit>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      moho::WeakPtr<moho::Unit>::sType = type;
    }
    return type;
  }

  struct CUnitCommandCommandEventLinkView
  {
    std::uint8_t pad_0000_0034[0x34];
    moho::Broadcaster mCommandEventListenerHead;
  };

  static_assert(
    offsetof(CUnitCommandCommandEventLinkView, mCommandEventListenerHead) == 0x34,
    "CUnitCommandCommandEventLinkView::mCommandEventListenerHead offset must be 0x34"
  );

  [[nodiscard]] moho::Broadcaster* CommandEventListenerHead(moho::CUnitCommand* const command) noexcept
  {
    if (!command) {
      return nullptr;
    }

    auto* const view = reinterpret_cast<CUnitCommandCommandEventLinkView*>(command);
    return &view->mCommandEventListenerHead;
  }

  void WakeTaskThreadForImmediateTick(moho::CTaskThread* const ownerThread)
  {
    if (ownerThread == nullptr) {
      return;
    }

    ownerThread->mPendingFrames = 0;
    if (ownerThread->mStaged) {
      ownerThread->Unstage();
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005FAD60 (FUN_005FAD60, Moho::CUnitSacrificeTask::CUnitSacrificeTask)
   *
   * What it does:
   * Initializes one detached sacrifice-task lane with default listener-link,
   * null current-command pointer, and cleared weak target lane.
   */
  CUnitSacrificeTask::CUnitSacrificeTask()
    : CCommandTask()
    , CUnitSacrificeTaskListenerPad{}
    , Listener<ECommandEvent>()
    , mCommand(nullptr)
    , mTargetUnit{}
  {
    mListenerPad = 0;
    mListenerLink.ListResetLinks();
    mTargetUnit.ownerLinkSlot = nullptr;
    mTargetUnit.nextInOwner = nullptr;
  }

  /**
   * Address: 0x005FAD90 (FUN_005FAD90, Moho::CUnitSacrificeTask::CUnitSacrificeTask)
   *
   * What it does:
   * Initializes one sacrifice-task lane from parent command-task and command
   * payload ownership context.
   */
  CUnitSacrificeTask::CUnitSacrificeTask(CCommandTask* const parentTask, Unit* const targetUnit)
    : CCommandTask(parentTask)
    , CUnitSacrificeTaskListenerPad{}
    , Listener<ECommandEvent>()
    , mCommand(nullptr)
    , mTargetUnit{}
  {
    mListenerPad = 0;
    mListenerLink.ListResetLinks();
    mTargetUnit.ResetFromObject(targetUnit);

    if (mUnit != nullptr && mUnit->CommandQueue != nullptr) {
      mCommand = mUnit->CommandQueue->GetCurrentCommand();
      if (Broadcaster* const commandListenerHead = CommandEventListenerHead(mCommand); commandListenerHead != nullptr) {
        mListenerLink.ListLinkBefore(commandListenerHead);
      }
    }
  }

  /**
   * Address: 0x005FAE40 (FUN_005FAE40, Moho::CUnitSacrificeTask::~CUnitSacrificeTask)
   *
   * What it does:
   * Unlinks command/listener lanes, clears repairing-state ownership bits,
   * writes dispatch result state, and tears down weak-target ownership links.
   */
  CUnitSacrificeTask::~CUnitSacrificeTask()
  {
    mListenerLink.ListUnlink();

    if (mUnit != nullptr) {
      mUnit->UnitStateMask &= ~(1ull << UNITSTATE_Repairing);

      if (mTaskState == TASKSTATE_Waiting) {
        mUnit->FreeOgridRect();
      }

      if (mDispatchResult != nullptr) {
        if (mTaskState == TASKSTATE_Starting) {
          *mDispatchResult = static_cast<EAiResult>(1);
          static_cast<Entity*>(mUnit)->Destroy();
        } else {
          *mDispatchResult = static_cast<EAiResult>(2);
        }
      }
    }

    mTargetUnit.UnlinkFromOwnerChain();
    mListenerLink.ListUnlink();
  }

  /**
   * Address: 0x005FB8B0 (FUN_005FB8B0, Moho::CUnitSacrificeTask::operator new)
   *
   * What it does:
   * Allocates one sacrifice-task object and forwards constructor arguments
   * into in-place construction.
   */
  CUnitSacrificeTask* CUnitSacrificeTask::Create(CCommandTask* const parentTask, Unit* const targetUnit)
  {
    void* const storage = ::operator new(sizeof(CUnitSacrificeTask));
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitSacrificeTask(parentTask, targetUnit);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }

  /**
   * Address: 0x005FB830 (FUN_005FB830, listener callback lane)
   *
   * What it does:
   * Refreshes sacrifice target weak-unit ownership from current command target
   * payload, resets task state to preparing, and wakes owner task thread.
   */
  void CUnitSacrificeTask::OnEvent(ECommandEvent)
  {
    if (mTaskState >= TASKSTATE_Starting) {
      return;
    }

    Unit* commandTargetUnit = nullptr;
    if (mCommand != nullptr) {
      Entity* const commandTargetEntity = mCommand->mTarget.targetEntity.GetObjectPtr();
      commandTargetUnit = (commandTargetEntity != nullptr) ? commandTargetEntity->IsUnit() : nullptr;
    }

    mTargetUnit.Set(commandTargetUnit);
    mTaskState = TASKSTATE_Preparing;
    WakeTaskThreadForImmediateTick(mOwnerThread);
  }

  /**
   * Address: 0x005FF2C0 (FUN_005FF2C0, Moho::CUnitSacrificeTask::MemberDeserialize)
   *
   * What it does:
   * Deserializes sacrifice-task runtime state in binary lane order: command-task
   * base, current command pointer lane, then target weak unit lane.
   */
  void CUnitSacrificeTask::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Read(CachedCCommandTaskType(), static_cast<CCommandTask*>(this), ownerRef);
    archive->ReadPointer_CUnitCommand(&mCommand, &ownerRef);
    archive->Read(CachedWeakPtrUnitType(), &mTargetUnit, ownerRef);
  }

  /**
   * Address: 0x005FF360 (FUN_005FF360)
   *
   * What it does:
   * Serializes sacrifice-task runtime state in binary lane order: command-task
   * base, current command raw pointer lane, then target weak unit lane.
   */
  void CUnitSacrificeTask::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Write(CachedCCommandTaskType(), static_cast<const CCommandTask*>(this), ownerRef);

    gpg::RRef commandRef{};
    (void)gpg::RRef_CUnitCommand(&commandRef, mCommand);
    gpg::WriteRawPointer(archive, commandRef, gpg::TrackedPointerState::Unowned, ownerRef);

    archive->Write(CachedWeakPtrUnitType(), &mTargetUnit, ownerRef);
  }

  /**
   * Address: 0x005FD570 (FUN_005FD570)
   *
   * What it does:
   * Preserves one serializer-save thunk lane for `CUnitSacrificeTask`.
   */
  [[maybe_unused]] void CUnitSacrificeTaskMemberSerializeAdapterLaneA(
    const CUnitSacrificeTask* const task,
    gpg::WriteArchive* const archive
  )
  {
    task->MemberSerialize(archive);
  }

  /**
   * Address: 0x005FDCA0 (FUN_005FDCA0)
   *
   * What it does:
   * Alternate serializer-save thunk lane for `CUnitSacrificeTask`.
   */
  [[maybe_unused]] void CUnitSacrificeTaskMemberSerializeAdapterLaneB(
    const CUnitSacrificeTask* const task,
    gpg::WriteArchive* const archive
  )
  {
    task->MemberSerialize(archive);
  }
} // namespace moho
