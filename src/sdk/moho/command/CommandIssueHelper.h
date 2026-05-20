#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/command/SSTICommandConstantData.h"
#include "moho/command/SSTICommandVariableData.h"

namespace moho
{
  struct SSelectionNodeUserEntity;
  struct UserCommandIssueLocalEvent;

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

  struct CommandIssueLocalQueue
  {
    std::uint32_t mAllocatorProxy;       // +0x00
    UserCommandIssueLocalEvent** mSlots; // +0x04
    std::uint32_t mCapacity;             // +0x08
    std::uint32_t mReadIndex;            // +0x0C
    std::uint32_t mCount;                // +0x10
  };
  static_assert(sizeof(CommandIssueLocalQueue) == 0x14, "CommandIssueLocalQueue size must be 0x14");
  static_assert(offsetof(CommandIssueLocalQueue, mSlots) == 0x04, "CommandIssueLocalQueue::mSlots offset must be 0x04");
  static_assert(
    offsetof(CommandIssueLocalQueue, mCapacity) == 0x08, "CommandIssueLocalQueue::mCapacity offset must be 0x08"
  );
  static_assert(
    offsetof(CommandIssueLocalQueue, mReadIndex) == 0x0C, "CommandIssueLocalQueue::mReadIndex offset must be 0x0C"
  );
  static_assert(offsetof(CommandIssueLocalQueue, mCount) == 0x10, "CommandIssueLocalQueue::mCount offset must be 0x10");

  struct CommandIssueWeakSet
  {
    void* mAllocatorProxy;           // +0x00
    SSelectionNodeUserEntity* mHead; // +0x04
    std::uint32_t mSize;             // +0x08
  };
  static_assert(sizeof(CommandIssueWeakSet) == 0x0C, "CommandIssueWeakSet size must be 0x0C");
  static_assert(offsetof(CommandIssueWeakSet, mHead) == 0x04, "CommandIssueWeakSet::mHead offset must be 0x04");
  static_assert(offsetof(CommandIssueWeakSet, mSize) == 0x08, "CommandIssueWeakSet::mSize offset must be 0x08");

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
    CommandIssueLocalQueue mLocalQueue;       // +0x0B8
    CommandIssueWeakSet mCursorEntitySet;     // +0x0CC

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
