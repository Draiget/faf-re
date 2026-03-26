#pragma once
#include <cstddef>
#include <cstdint>

#include "Broadcaster.h"
#include "CUnitCommand.h"
#include "legacy/containers/Vector.h"
#include "moho/command/CmdDefs.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/misc/WeakPtr.h"

namespace moho
{
  class Unit;

  class CUnitCommandQueue : public Broadcaster
  {
  public:
    /**
     * Address: 0x006EDD30
     */
    int FindCommandIndex(CmdId cmdId) const;

    /**
     * Address: 0x006EDF80
     */
    bool RemoveCommandFromQueue(const CUnitCommand* command);

    /**
     * Address: 0x006EDEF0
     */
    bool RemoveCommandFromQueue(int index);

    /**
     * Address: 0x006EE2D0 (FUN_006EE2D0)
     *
     * What it does:
     * Clears queued commands in reverse order and marks owner sync state dirty
     * for specific head command families.
     */
    void ClearCommandQueue();

    /**
     * Address: 0x006EE2D0 (FUN_006EE2D0)
     *
     * Applies pre-destroy queue cleanup and marks owning unit dirty when needed.
     */
    void MarkForUnitKillCleanup();

    /**
     * Address: 0x006A4D40 (FUN_006A4D40)
     *
     * Runs full queue teardown logic (list unlink + internal buffers cleanup).
     */
    void DestroyForUnitKillCleanup();

  public:
    Unit* mUnit;
    msvc8::vector<WeakPtr<CUnitCommand>> mCommandVec;
    EUnitCommandType mCommandType; // mirrors queue head command family
    int32_t unk0;
    bool mNeedsRefresh;
    std::uint8_t pad_25[3];
  };

  static_assert(offsetof(CUnitCommandQueue, mUnit) == 0x08, "CUnitCommandQueue::mUnit offset must be 0x08");
  static_assert(offsetof(CUnitCommandQueue, mCommandVec) == 0x0C, "CUnitCommandQueue::mCommandVec offset must be 0x0C");
  static_assert(
    offsetof(CUnitCommandQueue, mCommandType) == 0x1C, "CUnitCommandQueue::mCommandType offset must be 0x1C"
  );
  static_assert(offsetof(CUnitCommandQueue, unk0) == 0x20, "CUnitCommandQueue::unk0 offset must be 0x20");
  static_assert(
    offsetof(CUnitCommandQueue, mNeedsRefresh) == 0x24, "CUnitCommandQueue::mNeedsRefresh offset must be 0x24"
  );
  static_assert(sizeof(CUnitCommandQueue) == 0x28, "CUnitCommandQueue size must be 0x28");
} // namespace moho
