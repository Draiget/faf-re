#include "CUnitCommandQueue.h"

#include <cstddef>

#include "moho/unit/core/Unit.h"

using namespace moho;

namespace
{
  void RefreshQueueHeadType(CUnitCommandQueue& queue)
  {
    if (queue.mCommandVec.empty()) {
      queue.mCommandType = EUnitCommandType::UNITCOMMAND_None;
      return;
    }

    CUnitCommand* const headCommand = queue.mCommandVec.front().GetObjectPtr();
    queue.mCommandType = headCommand ? headCommand->mVarDat.mCmdType : EUnitCommandType::UNITCOMMAND_None;
  }

  [[nodiscard]] bool ShouldMarkOwnerSyncStateForQueueHead(const CUnitCommandQueue& queue)
  {
    if (queue.mCommandVec.empty()) {
      return false;
    }

    const CUnitCommand* const headCommand = queue.mCommandVec.front().GetObjectPtr();
    if (!headCommand) {
      return false;
    }

    switch (headCommand->mVarDat.mCmdType) {
    case EUnitCommandType::UNITCOMMAND_BuildSiloTactical:
    case EUnitCommandType::UNITCOMMAND_BuildSiloNuke:
    case EUnitCommandType::UNITCOMMAND_BuildFactory:
    case EUnitCommandType::UNITCOMMAND_Reclaim:
    case EUnitCommandType::UNITCOMMAND_Repair:
    case EUnitCommandType::UNITCOMMAND_Capture:
    case EUnitCommandType::UNITCOMMAND_TransportLoadUnits:
    case EUnitCommandType::UNITCOMMAND_TransportReverseLoadUnits:
    case EUnitCommandType::UNITCOMMAND_TransportUnloadUnits:
    case EUnitCommandType::UNITCOMMAND_TransportUnloadSpecificUnits:
    case EUnitCommandType::UNITCOMMAND_Upgrade:
    case EUnitCommandType::UNITCOMMAND_Dock:
      return true;
    default:
      return false;
    }
  }

  void MarkOwningUnitSyncDirty(Unit* const unit)
  {
    if (!unit) {
      return;
    }
    unit->MarkNeedsSyncGameData();
  }

  void ReleaseCommandVectorStorage(msvc8::vector<WeakPtr<CUnitCommand>>& commandVec)
  {
    while (!commandVec.empty()) {
      commandVec.back().ResetFromObject(nullptr);
      commandVec.pop_back();
    }
    commandVec = msvc8::vector<WeakPtr<CUnitCommand>>{};
  }
} // namespace

/**
 * Address: 0x006EDD30 (FUN_006EDD30)
 *
 * What it does:
 * Finds the first queued command with the requested command id.
 */
int CUnitCommandQueue::FindCommandIndex(const CmdId cmdId) const
{
  for (std::size_t i = 0; i < mCommandVec.size(); ++i) {
    const CUnitCommand* const command = mCommandVec[i].GetObjectPtr();
    if (command && command->mConstDat.cmd == cmdId) {
      return static_cast<int>(i);
    }
  }

  return -1;
}

/**
 * Address: 0x006EDF80 (FUN_006EDF80)
 *
 * What it does:
 * Finds and removes a queued command by pointer identity.
 */
bool CUnitCommandQueue::RemoveCommandFromQueue(const CUnitCommand* command)
{
  for (std::size_t i = 0; i < mCommandVec.size(); ++i) {
    if (mCommandVec[i].GetObjectPtr() == command) {
      return RemoveCommandFromQueue(static_cast<int>(i));
    }
  }

  return false;
}

/**
 * Address: 0x006EDEF0 (FUN_006EDEF0)
 *
 * What it does:
 * Removes a queued command by index and marks queue refresh state.
 */
bool CUnitCommandQueue::RemoveCommandFromQueue(const int index)
{
  if (index < 0 || static_cast<std::size_t>(index) >= mCommandVec.size()) {
    return false;
  }

  const std::size_t queueIndex = static_cast<std::size_t>(index);
  if (queueIndex == 0u && ShouldMarkOwnerSyncStateForQueueHead(*this)) {
    MarkOwningUnitSyncDirty(mUnit);
  }

  CUnitCommand* const command = mCommandVec[queueIndex].GetObjectPtr();
  if (command) {
    command->RemoveUnit(mUnit, mCommandVec);
  } else {
    EraseWeakVectorEntry(mCommandVec, queueIndex);
  }

  RefreshQueueHeadType(*this);
  mNeedsRefresh = true;
  return true;
}

/**
 * Address: 0x006EE2D0 (FUN_006EE2D0)
 *
 * What it does:
 * Clears queued commands in reverse order, marks owner sync dirty when needed,
 * and resets queue-local cleanup state.
 */
void CUnitCommandQueue::ClearCommandQueue()
{
  if (ShouldMarkOwnerSyncStateForQueueHead(*this)) {
    MarkOwningUnitSyncDirty(mUnit);
  }

  while (!mCommandVec.empty()) {
    CUnitCommand* const command = mCommandVec.back().GetObjectPtr();
    if (command) {
      command->RemoveUnit(mUnit, mCommandVec);
    } else {
      EraseWeakVectorEntry(mCommandVec, mCommandVec.size() - 1u);
    }
  }

  mCommandType = EUnitCommandType::UNITCOMMAND_None;
  unk0 = 0;
  mNeedsRefresh = true;
}

/**
 * Address: 0x006EE2D0 (FUN_006EE2D0)
 *
 * What it does:
 * Runs pre-destroy queue cleanup only.
 */
void CUnitCommandQueue::MarkForUnitKillCleanup()
{
  ClearCommandQueue();
}

/**
 * Address: 0x006A4D40 (FUN_006A4D40)
 *
 * What it does:
 * Runs full queue teardown (clear + vector storage release + broadcaster unlink reset).
 */
void CUnitCommandQueue::DestroyForUnitKillCleanup()
{
  ClearCommandQueue();
  ReleaseCommandVectorStorage(mCommandVec);
  ListUnlink();
}
