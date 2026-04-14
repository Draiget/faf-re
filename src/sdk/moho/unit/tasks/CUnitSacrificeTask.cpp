#include "moho/unit/tasks/CUnitSacrificeTask.h"

#include <cstddef>
#include <cstdint>
#include <new>

#include "moho/unit/Broadcaster.h"
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

  [[nodiscard]] moho::Broadcaster* CommandEventListenerHead(moho::CUnitCommand* const command) noexcept
  {
    if (!command) {
      return nullptr;
    }

    auto* const view = reinterpret_cast<CUnitCommandCommandEventLinkView*>(command);
    return &view->mCommandEventListenerHead;
  }
} // namespace

namespace moho
{
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

  void CUnitSacrificeTask::OnEvent(ECommandEvent)
  {}
} // namespace moho
