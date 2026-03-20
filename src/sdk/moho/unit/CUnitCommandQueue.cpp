#include "CUnitCommandQueue.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>

using namespace moho;

namespace
{
  constexpr std::ptrdiff_t kUnitQueueHeadClearLatchOffset = 0x0A2;

  [[nodiscard]] bool IsHeadCommandRepeatLatchType(const CUnitCommandQueue& queue)
  {
    if (queue.mCommandVec.empty()) {
      return false;
    }

    const CUnitCommand* const headCommand = queue.mCommandVec.front().get();
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

  void MarkOwningUnitQueueClearLatch(Unit* const unit)
  {
    if (!unit) {
      return;
    }

    // TODO(layout): this byte is still an unresolved Unit base-field in current SDK layouts.
    auto* const raw = reinterpret_cast<std::uint8_t*>(unit);
    raw[kUnitQueueHeadClearLatchOffset] = 1;
  }

  void ReleaseCommandVectorStorage(gpg::core::FastVector<boost::shared_ptr<CUnitCommand>>& commandVec)
  {
    commandVec = gpg::core::FastVector<boost::shared_ptr<CUnitCommand>>{};
  }

  void UnlinkBroadcasterNode(Broadcaster& node)
  {
    if (node.unk0) {
      node.unk0->unk1 = node.unk1;
    }
    if (node.unk1) {
      node.unk1->unk0 = node.unk0;
    }
    node.unk1 = &node;
    node.unk0 = &node;
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
  const auto it =
    std::find_if(mCommandVec.begin(), mCommandVec.end(), [cmdId](const boost::shared_ptr<CUnitCommand>& command) {
    return command && command->mConstDat.cmd == cmdId;
  });
  if (it == mCommandVec.end()) {
    return -1;
  }

  return static_cast<int>(std::distance(mCommandVec.begin(), it));
}

/**
 * Address: 0x006EDF80 (FUN_006EDF80)
 *
 * What it does:
 * Finds and removes a queued command by pointer identity.
 */
bool CUnitCommandQueue::RemoveCommandFromQueue(const CUnitCommand* command)
{
  if (!command) {
    return false;
  }

  const auto it = std::find_if(
    mCommandVec.begin(), mCommandVec.end(), [command](const boost::shared_ptr<CUnitCommand>& queuedCommand) {
    return queuedCommand.get() == command;
  }
  );
  if (it == mCommandVec.end()) {
    return false;
  }

  const int index = static_cast<int>(std::distance(mCommandVec.begin(), it));
  return RemoveCommandFromQueue(index);
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

  if (index == 0 && IsHeadCommandRepeatLatchType(*this)) {
    MarkOwningUnitQueueClearLatch(mUnit);
  }

  mCommandVec.erase(mCommandVec.begin() + index);
  mNeedsRefresh = true;
  return true;
}

/**
 * Address: 0x006EE2D0 (FUN_006EE2D0)
 *
 * What it does:
 * Clears queued commands in reverse order and resets queue-local cleanup state.
 */
void CUnitCommandQueue::ClearCommandQueue()
{
  if (IsHeadCommandRepeatLatchType(*this)) {
    MarkOwningUnitQueueClearLatch(mUnit);
  }

  for (int i = static_cast<int>(mCommandVec.size()) - 1; i >= 0; --i) {
    RemoveCommandFromQueue(i);
  }

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
  UnlinkBroadcasterNode(*this);
}
