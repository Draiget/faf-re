#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "legacy/containers/Deque.h"
#include "moho/command/CmdDefs.h"
#include "moho/command/SSTICommandConstantData.h"
#include "moho/command/SSTICommandVariableData.h"
#include "moho/command/UserTarget.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/WeakEntitySet.h"

namespace moho
{

  struct CommandIssueObserverLink
  {
    void* mOwnerLinkSlot;            // +0x00
    CommandIssueObserverLink* mNext; // +0x04
  };
  static_assert(sizeof(CommandIssueObserverLink) == 0x08, "CommandIssueObserverLink size must be 0x08");

  struct CommandIssueObserverChain
  {
    CommandIssueObserverLink* mHead; // +0x00

    /**
     * Inlined block from FUN_008B3F80.
     *
     * What it does:
     * Detaches every helper-owned queue/manager back-link node without
     * releasing node storage; ownership belongs to the linked queue entries.
     */
    ~CommandIssueObserverChain() noexcept;
  };
  static_assert(sizeof(CommandIssueObserverChain) == 0x04, "CommandIssueObserverChain size must be 0x04");

  /**
   * Kind of one local command-issue event. The values are the literals the
   * queueing bodies pass to the event constructor (`mov ecx, N` before the
   * call to 0x008B3DC0): 0 at 0x008B4720, 1 at 0x008B4960, 2 at 0x008B49D0,
   * 3 at 0x008B48F1, 4 at 0x008B4A5F, 5 at 0x008B4AE3.
   */
  enum class ECommandIssueEvent : std::uint32_t
  {
    SelectUnit = 0,
    IncreaseCount = 1,
    DecreaseCount = 2,
    DeselectUnit = 3,
    SetTarget = 4,
    SetCommandType = 5,
  };

  /**
   * One edit the UI made to a command before the sim confirmed it: the
   * helper keeps these in `mLocalQueue` and replays them over the last
   * replicated command state until the sim's beat catches up
   * (`UserCommandIssueHelper::AdvanceLocalEventsToBeat`, 0x008B4C20).
   *
   * Both special members the binary emits out of line are the implicit ones:
   *
   * Address: 0x008B56F0 (FUN_008B56F0 -- the implicit copy constructor:
   * member-wise, the unit set through its range constructor 0x00831310,
   * `mTarget` through 0x008B40F0, `mCells` through 0x00552C90; `+0x34` is
   * padding and is not copied. Reached from `msvc8::deque::push_back`
   * 0x008B4E80.)
   * Address: 0x008B4800 (FUN_008B4800 -- the implicit destructor, members in
   * reverse: `mCells` back to inline storage, `mTarget`'s weak link unlinked,
   * `mUnits` erased (0x007B33B0) and its head freed.)
   */
  struct UserCommandIssueLocalEvent
  {
    CmdId mCmdId;                           // +0x00: the sim beat the edit is due on
    ECommandIssueEvent mType;               // +0x04
    WeakUnitSetUserUnit mUnits;             // +0x08: SelectUnit / DeselectUnit
    std::int32_t mCount;                    // +0x14: IncreaseCount / DecreaseCount
    UserTarget mTarget;                     // +0x18: SetTarget
    EUnitCommandType mCommandType;          // +0x30: SetCommandType
    std::uint8_t mPad34[0x04];              // +0x34
    gpg::fastvector_n<SOCellPos, 2> mCells; // +0x38

    /**
     * Address: 0x008B3DC0 (FUN_008B3DC0, sub_8B3DC0)
     *
     * IDA signature:
     * Moho::UserCommandIssueLocalEvent *__userpurge sub_8B3DC0@<eax>(
     *     Moho::UserCommandIssueLocalEvent *this@<esi>, int type@<ecx>, int cmdId);
     *
     * What it does:
     * Stores the beat and kind, brings the unit set up empty (head sentinel
     * through 0x007B4640), zeroes the count and the target's type and weak
     * link, and points the cell vector at its inline storage. The target
     * position, `mCommandType` and the padding are left unwritten.
     */
    UserCommandIssueLocalEvent(CmdId cmdId, ECommandIssueEvent type);
  };

  static_assert(offsetof(UserCommandIssueLocalEvent, mType) == 0x04, "UserCommandIssueLocalEvent::mType offset must be 0x04");
  static_assert(offsetof(UserCommandIssueLocalEvent, mUnits) == 0x08, "UserCommandIssueLocalEvent::mUnits offset must be 0x08");
  static_assert(offsetof(UserCommandIssueLocalEvent, mCount) == 0x14, "UserCommandIssueLocalEvent::mCount offset must be 0x14");
  static_assert(offsetof(UserCommandIssueLocalEvent, mTarget) == 0x18, "UserCommandIssueLocalEvent::mTarget offset must be 0x18");
  static_assert(
    offsetof(UserCommandIssueLocalEvent, mCommandType) == 0x30, "UserCommandIssueLocalEvent::mCommandType offset must be 0x30"
  );
  static_assert(offsetof(UserCommandIssueLocalEvent, mCells) == 0x38, "UserCommandIssueLocalEvent::mCells offset must be 0x38");
  static_assert(sizeof(UserCommandIssueLocalEvent) == 0x50, "UserCommandIssueLocalEvent size must be 0x50");

  struct UserCommandIssueHelper
  {
    CommandIssueObserverChain mObserverLinks; // +0x000
    SSTICommandConstantData mConstantData;    // +0x004
    SSTICommandVariableData mVariableData;    // +0x040
    std::uint8_t mVariableDataTailPad[0x04];  // +0x0AC
    std::uint8_t mReservedB0;                 // +0x0B0
    std::uint8_t mDeleteWhenDue;              // +0x0B1
    std::uint8_t mVariableDataDirty;          // +0x0B2
    std::uint8_t mReservedB3;                 // +0x0B3
    std::int32_t mDueSeqNo;                   // +0x0B4
    /// Local edits not yet confirmed by the sim, oldest first. Block size 1
    /// (0x50-byte element), so each map slot owns one event.
    msvc8::deque<UserCommandIssueLocalEvent> mLocalQueue; // +0x0B8
    /// Entities the command applies to, rebuilt from `mVariableData.mEntIds`
    /// plus the queued select/deselect edits (`GetEntitiesUnderCursor`, 0x008B43F0).
    WeakEntitySetUserEntity mCursorEntitySet;             // +0x0CC

    /**
     * Address: 0x008B3EC0 (FUN_008B3EC0, struct_CommandIssueHelper::struct_CommandIssueHelper)
     *
     * What it does:
     * Copies command constant data, initializes variable command payload
     * state and local queue lanes, and creates an empty cursor weak-set.
     */
    UserCommandIssueHelper(
      const SSTICommandConstantData& constantData,
      std::uint8_t deleteWhenDue,
      std::int32_t dueSeqNo
    );

    /**
     * Address: 0x008B4C20 (FUN_008B4C20)
     *
     * What it does:
     * Retires this helper once its due sequence is reached, otherwise drains
     * due local command-issue events and marks variable data dirty.
     */
    void AdvanceLocalEventsToBeat(std::int32_t beat) noexcept;

    /**
     * Address: 0x008B3F80 (FUN_008B3F80, struct_CommandIssueHelper::~struct_CommandIssueHelper)
     * Mangled: ??1struct_CommandIssueHelper@@QAE@@Z
     *
     * What it does:
     * Removes this helper from the active session command map, releases its
     * cursor weak-set and local event queue, then lets typed command payload
     * members destroy in source order.
     */
    ~UserCommandIssueHelper() noexcept;
  };

  static_assert(offsetof(UserCommandIssueHelper, mObserverLinks) == 0x000, "UserCommandIssueHelper::mObserverLinks offset must be 0x000");
  static_assert(offsetof(UserCommandIssueHelper, mConstantData) == 0x004, "UserCommandIssueHelper::mConstantData offset must be 0x004");
  static_assert(offsetof(UserCommandIssueHelper, mVariableData) == 0x040, "UserCommandIssueHelper::mVariableData offset must be 0x040");
  static_assert(
    offsetof(UserCommandIssueHelper, mVariableDataTailPad) == 0x0AC,
    "UserCommandIssueHelper::mVariableDataTailPad offset must be 0x0AC"
  );
  static_assert(offsetof(UserCommandIssueHelper, mReservedB0) == 0x0B0, "UserCommandIssueHelper::mReservedB0 offset must be 0x0B0");
  static_assert(offsetof(UserCommandIssueHelper, mDeleteWhenDue) == 0x0B1, "UserCommandIssueHelper::mDeleteWhenDue offset must be 0x0B1");
  static_assert(
    offsetof(UserCommandIssueHelper, mVariableDataDirty) == 0x0B2,
    "UserCommandIssueHelper::mVariableDataDirty offset must be 0x0B2"
  );
  static_assert(offsetof(UserCommandIssueHelper, mDueSeqNo) == 0x0B4, "UserCommandIssueHelper::mDueSeqNo offset must be 0x0B4");
  static_assert(offsetof(UserCommandIssueHelper, mLocalQueue) == 0x0B8, "UserCommandIssueHelper::mLocalQueue offset must be 0x0B8");
  static_assert(offsetof(UserCommandIssueHelper, mCursorEntitySet) == 0x0CC, "UserCommandIssueHelper::mCursorEntitySet offset must be 0x0CC");
  static_assert(sizeof(UserCommandIssueHelper) == 0x0D8, "UserCommandIssueHelper size must be 0x0D8");
} // namespace moho
