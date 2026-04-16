#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/Listener.h"
#include "moho/misc/WeakPtr.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/ECommandEvent.h"
#include "moho/unit/tasks/CBuildTaskHelper.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
}

namespace moho
{
  class IAiCommandDispatchImpl;
  class CUnitCommand;
  class Unit;

  struct CUnitRepairTaskListenerPad
  {
    std::uint32_t mListenerPad{};
  };

  static_assert(sizeof(CUnitRepairTaskListenerPad) == 0x04, "CUnitRepairTaskListenerPad size must be 0x04");

  /**
   * Address: 0x005F8C80 (??0CUnitRepairTask@Moho@@QAE@@Z)
   *
   * What it does:
   * Builds the repair-task command/listener subobjects, initializes the shared
   * build helper, binds the target weak lane, and primes the repair mode flags.
   */
  class CUnitRepairTask : public CCommandTask, public CUnitRepairTaskListenerPad, public Listener<ECommandEvent>
  {
  public:
    /**
     * Address: 0x005FED70 (FUN_005FED70, Moho::CUnitRepairTask::MemberDeserialize)
     *
     * What it does:
     * Deserializes repair-task runtime state in binary lane order: command-task
     * base, helper lane, command pointer lane, weak target lanes, then flags.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005FEEC0 (FUN_005FEEC0)
     *
     * What it does:
     * Serializes repair-task runtime state (base command-task lane, build
     * helper, bound command pointer, weak target lanes, and state flags).
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x005F8C80 (??0CUnitRepairTask@Moho@@QAE@@Z)
     *
     * What it does:
     * Builds the repair-task command/listener subobjects, initializes the shared
     * build helper, binds the target weak lane, and primes the repair mode flags.
     */
    CUnitRepairTask(IAiCommandDispatchImpl* dispatchTask, Unit* targetUnit, bool isSiloBuild);

  public:
    CBuildTaskHelper mBuildHelper;  // 0x40
    CUnitCommand* mCommand;         // 0x84
    WeakPtr<Unit> mTargetUnit;      // 0x88
    WeakPtr<Unit> mBuildTargetUnit; // 0x90
    bool mInPosition;               // 0x98
    bool mIsSilo;                   // 0x99
    bool mGuardAssistMode;          // 0x9A
    bool mInheritingWork;           // 0x9B
  };

  static_assert(sizeof(CUnitRepairTask) == 0x9C, "CUnitRepairTask size must be 0x9C");
  static_assert(offsetof(CUnitRepairTask, mBuildHelper) == 0x40, "CUnitRepairTask::mBuildHelper offset must be 0x40");
  static_assert(offsetof(CUnitRepairTask, mCommand) == 0x84, "CUnitRepairTask::mCommand offset must be 0x84");
  static_assert(offsetof(CUnitRepairTask, mTargetUnit) == 0x88, "CUnitRepairTask::mTargetUnit offset must be 0x88");
  static_assert(
    offsetof(CUnitRepairTask, mBuildTargetUnit) == 0x90,
    "CUnitRepairTask::mBuildTargetUnit offset must be 0x90"
  );
  static_assert(offsetof(CUnitRepairTask, mInPosition) == 0x98, "CUnitRepairTask::mInPosition offset must be 0x98");
  static_assert(offsetof(CUnitRepairTask, mIsSilo) == 0x99, "CUnitRepairTask::mIsSilo offset must be 0x99");
  static_assert(
    offsetof(CUnitRepairTask, mGuardAssistMode) == 0x9A, "CUnitRepairTask::mGuardAssistMode offset must be 0x9A"
  );
  static_assert(
    offsetof(CUnitRepairTask, mInheritingWork) == 0x9B, "CUnitRepairTask::mInheritingWork offset must be 0x9B"
  );
} // namespace moho
