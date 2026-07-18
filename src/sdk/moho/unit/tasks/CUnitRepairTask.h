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

    /**
     * Address: 0x005F8E20 (FUN_005F8E20, ??1CUnitRepairTask@Moho@@QAE@@Z body)
     * Scalar deleting dtor thunk: 0x005F8FE0 (FUN_005F8FE0, vtable slot 0)
     *
     * IDA signature:
     * int __stdcall Moho::CUnitRepairTask::~CUnitRepairTask(Moho::CUnitRepairTask *this);
     *
     * What it does:
     * Runs the "ClearWork" unit script, detaches the embedded command-event
     * listener, clears the owner unit's repairing state bit, zeros its work
     * progress and builder aim target, releases the reserved ogrid footprint
     * when still held mid-prep, clears the build-target unit's no-reclaim bit,
     * stops the shared build helper, records the task's dispatch result, and
     * unlinks the build-target/target weak lanes before base/member teardown.
     */
    ~CUnitRepairTask() override;

    /**
     * Address: 0x005F9370 (FUN_005F9370, Moho::CUnitRepairTask::TaskTick)
     *
     * VFTABLE SLOT: 1
     *
     * What it does:
     * Repair/assist build-task state machine (Preparing/Waiting/Starting/
     * Processing/Complete): bails when the target is gone, is the owner, or is
     * fully healed and CanRepair() clears it; re-homes onto a being-built unit's
     * factory creator or an upgrading unit's focus; moves the builder into build
     * range; aims the builder arm; faces the target when required; drives the
     * shared build helper to completion. Returns the scheduler code
     * (-1 done / 0 advance / 1 wait / 10 paused).
     */
    int Execute() override;

    /**
     * Address: 0x005F9D60 (FUN_005F9D60, Moho::CUnitRepairTask::OnEvent)
     *
     * VFTABLE SLOT: 0 (Listener<ECommandEvent> sub-object vtable)
     *
     * What it does:
     * Command-event handler: cancels the active repair (clears the build-target's
     * NoReclaim bit, zeros owner work progress, stops the build helper, unlinks
     * the build-target lane), rebinds the target lane from the bound command's
     * focus, resets state to Preparing, and resumes the owning task thread.
     */
    void OnEvent(ECommandEvent event) override;

  private:
    /**
     * Address: 0x005F9230 (FUN_005F9230, Moho::CUnitRepairTask::CanRepair)
     *
     * What it does:
     * Returns whether the target may currently be repaired: false when the target
     * needs refuel (fuel-using blueprint with fuel ratio below full) or is a
     * SHIELD whose shielded focus is itself damaged; true otherwise.
     */
    [[nodiscard]] bool CanRepair();

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
