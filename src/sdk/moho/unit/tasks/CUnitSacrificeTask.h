#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/Listener.h"
#include "moho/misc/WeakPtr.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/ECommandEvent.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
}

namespace moho
{
  class CUnitCommand;
  class Unit;

  struct CUnitSacrificeTaskListenerPad
  {
    std::uint32_t mListenerPad{};
  };

  static_assert(sizeof(CUnitSacrificeTaskListenerPad) == 0x04, "CUnitSacrificeTaskListenerPad size must be 0x04");

  /**
   * Runtime owner for unit-sacrifice command task state.
   */
  class CUnitSacrificeTask : public CCommandTask, public CUnitSacrificeTaskListenerPad, public Listener<ECommandEvent>
  {
  public:
    /**
     * Address: 0x005FF2C0 (FUN_005FF2C0, Moho::CUnitSacrificeTask::MemberDeserialize)
     *
     * What it does:
     * Deserializes sacrifice-task runtime state (base command-task lane, current
     * command pointer lane, and weak target unit lane).
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005FF360 (FUN_005FF360)
     *
     * What it does:
     * Serializes sacrifice-task runtime state (base command-task lane, current
     * command pointer lane, and weak target unit lane).
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x005FAD60 (FUN_005FAD60, Moho::CUnitSacrificeTask::CUnitSacrificeTask)
     *
     * What it does:
     * Initializes one detached sacrifice-task lane with default listener-link,
     * null current-command pointer, and cleared weak target lane.
     */
    CUnitSacrificeTask();

    /**
     * Address: 0x005FAD90 (FUN_005FAD90, Moho::CUnitSacrificeTask::CUnitSacrificeTask)
     *
     * What it does:
     * Initializes one sacrifice-task lane from parent command-task and command
     * payload ownership context.
     */
    CUnitSacrificeTask(CCommandTask* parentTask, Unit* targetUnit);

    /**
     * Address: 0x005FAE40 (FUN_005FAE40, Moho::CUnitSacrificeTask::~CUnitSacrificeTask)
     *
     * What it does:
     * Unlinks command/listener lanes, clears repairing-state ownership bits,
     * writes dispatch result state, and tears down weak-target ownership links.
     */
    ~CUnitSacrificeTask() override;

    /**
     * Address: 0x005FB8B0 (FUN_005FB8B0, Moho::CUnitSacrificeTask::operator new)
     *
     * What it does:
     * Allocates one sacrifice-task object and forwards constructor arguments
     * into in-place construction.
     */
    [[nodiscard]] static CUnitSacrificeTask* Create(CCommandTask* parentTask, Unit* targetUnit);

    /**
     * Address: 0x005FB830 (FUN_005FB830, Moho::CUnitSacrificeTask::OnEvent)
     *
     * What it does:
     * Refreshes target-unit weak ownership from current command payload,
     * resets task state to preparing, and wakes the owner thread for an
     * immediate tick.
     */
    void OnEvent(ECommandEvent event) override;

  public:
    CUnitCommand* mCommand; // +0x40
    WeakPtr<Unit> mTargetUnit; // +0x44
  };

  static_assert(sizeof(CUnitSacrificeTask) == 0x4C, "CUnitSacrificeTask size must be 0x4C");
  static_assert(offsetof(CUnitSacrificeTask, mCommand) == 0x40, "CUnitSacrificeTask::mCommand offset must be 0x40");
  static_assert(
    offsetof(CUnitSacrificeTask, mTargetUnit) == 0x44, "CUnitSacrificeTask::mTargetUnit offset must be 0x44"
  );
} // namespace moho
