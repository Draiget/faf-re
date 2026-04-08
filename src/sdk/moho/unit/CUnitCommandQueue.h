#pragma once
#include <cstddef>
#include <cstdint>

#include "Broadcaster.h"
#include "CUnitCommand.h"
#include "legacy/containers/Vector.h"
#include "moho/command/CmdDefs.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/misc/WeakPtr.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
  class RRef;
  class RType;
  class SerConstructResult;
  class SerSaveConstructArgsResult;
} // namespace gpg

namespace moho
{
  class Unit;

  class CUnitCommandQueue : public Broadcaster
  {
  public:
    /**
     * Address: 0x006A4CD0 (FUN_006A4CD0, ??0CUnitCommandQueue@Moho@@QAE@PAVUnit@1@@Z)
     *
     * What it does:
     * Initializes queue owner pointer, command lanes, and queue-head state.
     */
    explicit CUnitCommandQueue(Unit* unit);

    /**
     * Address: 0x006A4D40 (FUN_006A4D40, ??1CUnitCommandQueue@Moho@@QAE@XZ)
     *
     * What it does:
     * Clears queued commands, releases weak-command storage, and unlinks the
     * queue from broadcaster intrusive lanes.
     */
    ~CUnitCommandQueue();

    /**
     * Address: 0x006EE8C0 (FUN_006EE8C0,
     * ?MemberSaveConstructArgs@CUnitCommandQueue@Moho@@AAEXAAVWriteArchive@gpg@@HABVRRef@4@AAVSerSaveConstructArgsResult@4@@Z)
     *
     * What it does:
     * Saves construct payload (`Unit*` owner) as unowned tracked-pointer data.
     */
    void MemberSaveConstructArgs(
      gpg::WriteArchive& archive,
      int version,
      const gpg::RRef& ownerRef,
      gpg::SerSaveConstructArgsResult& result
    );

    /**
     * Address: 0x006EEAC0 (FUN_006EEAC0,
     * ?MemberConstruct@CUnitCommandQueue@Moho@@CAXAAVReadArchive@gpg@@HABVRRef@4@AAVSerConstructResult@4@@Z)
     *
     * What it does:
     * Reads construct payload and allocates one `CUnitCommandQueue`.
     */
    static void MemberConstruct(
      gpg::ReadArchive& archive,
      int version,
      const gpg::RRef& ownerRef,
      gpg::SerConstructResult& result
    );

    /**
     * Address: 0x006F9690 (FUN_006F9690, sub_6F9690)
     *
     * What it does:
     * Loads queue base/vector/type lanes and marks UI refresh state dirty.
     */
    void MemberDeserialize(gpg::ReadArchive& archive);

    /**
     * Address: 0x006F9750 (FUN_006F9750, sub_6F9750)
     *
     * What it does:
     * Saves queue base/vector/type lanes and queue local counter lane.
     */
    void MemberSerialize(gpg::WriteArchive& archive) const;

    /**
     * Address: 0x006EDAA0 (FUN_006EDAA0, constructor preregisters RTTI)
     *
     * What it does:
     * Resolves/refetches reflection descriptor for CUnitCommandQueue.
     */
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x006EDD30
     */
    int FindCommandIndex(CmdId cmdId) const;

    /**
     * Address: 0x006EDBF0 (FUN_006EDBF0, ?GetCurrentCommand@CUnitCommandQueue@Moho@@QAEPAVCUnitCommand@2@XZ)
     *
     * What it does:
     * Returns the first queued command, or `nullptr` when the queue is empty
     * or the head weak pointer is expired.
     */
    CUnitCommand* GetCurrentCommand();

    /**
     * Address: 0x006EDC20 (FUN_006EDC20, ?GetNextCommand@CUnitCommandQueue@Moho@@QAEPAVCUnitCommand@2@XZ)
     *
     * What it does:
     * Returns the second queued command, or `nullptr` when fewer than two
     * commands are available or the second weak pointer is expired.
     */
    CUnitCommand* GetNextCommand();

    /**
     * Address: 0x006EDC50 (FUN_006EDC50, ?GetLastCommand@CUnitCommandQueue@Moho@@QAEPAVCUnitCommand@2@XZ)
     *
     * What it does:
     * Returns the current queue-tail command, or `nullptr` when the queue is
     * empty or the tail weak pointer is expired.
     */
    CUnitCommand* GetLastCommand();

    /**
     * Address: 0x006EDC80 (FUN_006EDC80, ?GetCommandInQueue@CUnitCommandQueue@Moho@@QBEPAVCUnitCommand@2@I@Z)
     *
     * What it does:
     * Returns one command at `index`, or `nullptr` when index is out of range
     * or the weak pointer at that slot is expired.
     */
    CUnitCommand* GetCommandInQueue(unsigned int index) const;

    /**
     * Address: 0x00598B90 (FUN_00598B90, ?Finished@CUnitCommandQueue@Moho@@QAE_NXZ)
     *
     * What it does:
     * Returns true when the queue has no remaining command entries.
     */
    bool Finished() const;

    /**
     * Address: 0x006EDCB0 (FUN_006EDCB0, ?InsertCommandToQueue@CUnitCommandQueue@Moho@@QAEXPAVCUnitCommand@2@H@Z)
     *
     * What it does:
     * Inserts one command into this queue at `index`, updates sim command-digest
     * lanes, marks refresh state, and emits queue inserted-event.
     */
    void InsertCommandToQueue(CUnitCommand* command, int index);

    /**
     * Address: 0x006EDD80 (FUN_006EDD80, ?AddCommandToQueue@CUnitCommandQueue@Moho@@QAEXPAVCUnitCommand@2@@Z)
     *
     * What it does:
     * Chooses one insertion index for `command` (including patrol/follow-up
     * ordering lane) and forwards into `InsertCommandToQueue`.
     */
    void AddCommandToQueue(CUnitCommand* command);

    /**
     * Address: 0x006EDE70 (FUN_006EDE70, ?RemoveFirstCommandFromQueue@CUnitCommandQueue@Moho@@QAEXXZ)
     *
     * What it does:
     * Removes the current head command from this queue and emits refresh/changed
     * queue-status events.
     */
    void RemoveFirstCommandFromQueue();

    /**
     * Address: 0x006EDFC0 (FUN_006EDFC0, ?MoveFirstCommandToBackOfQueue@CUnitCommandQueue@Moho@@QAEXXZ)
     *
     * What it does:
     * Rotates the current queue-head command to queue tail and emits a
     * reorder queue-status event.
     */
    void MoveFirstCommandToBackOfQueue();

    /**
     * Address: 0x006EE0B0 (FUN_006EE0B0, ?MoveCommandToBackOfQueue@CUnitCommandQueue@Moho@@QAE_NI@Z)
     *
     * What it does:
     * Finds one queued command by command-object identity and moves that
     * entry to queue tail, then emits a reorder queue-status event.
     */
    bool MoveCommandToBackOfQueue(unsigned int index);

    /**
     * Address: 0x006EE220 (FUN_006EE220)
     *
     * What it does:
     * Finds one queued entry by command pointer and forwards to indexed
     * move-to-back queue reordering.
     */
    bool MoveCommandToBackOfQueue(const CUnitCommand* command);

    /**
     * Address: 0x006EDF80
     */
    bool RemoveCommandFromQueue(const CUnitCommand* command);

    /**
     * Address: 0x006EDEF0
     */
    bool RemoveCommandFromQueue(unsigned int index);

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

    /**
     * Address: 0x006EE360 (FUN_006EE360, ?AbortActiveTask@CUnitCommandQueue@Moho@@QAEXXZ)
     *
     * What it does:
     * Marks queue refresh state and emits one needs-refresh event for active
     * command abort transitions.
     */
    void AbortActiveTask();

    /**
     * Address: 0x006EE3C0 (FUN_006EE3C0, ?SetCommandCount@CUnitCommandQueue@Moho@@QAEXII@Z)
     *
     * What it does:
     * Sets one queued command count lane, updates command dirty flag state,
     * and applies queue-head/queue-removal transitions when count is zero.
     */
    void SetCommandCount(unsigned int index, unsigned int count);

  private:
    /**
     * Address: 0x006EE260 (FUN_006EE260, ?NeedsUIRefresh@CUnitCommandQueue@Moho@@AAE_NXZ)
     *
     * What it does:
     * Returns true when the current head command family requires owner sync/UI
     * refresh updates on queue-head transition.
     */
    bool NeedsUIRefresh();

  public:
    static gpg::RType* sType;

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
