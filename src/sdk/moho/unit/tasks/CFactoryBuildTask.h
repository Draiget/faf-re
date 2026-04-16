#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/WeakPtr.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CBuildTaskHelper.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
}

namespace moho
{
  class CUnitCommand;
  class IAiCommandDispatchImpl;
  struct RUnitBlueprint;
  class Unit;

  /**
   * VFTABLE: 0x00E1FADC
   * COL:  0x00E77588
   * Source hint: c:\work\rts\main\code\src\sim\AiUnitBuild.cpp
   *
   * Factory build task: drives factory-style unit construction from a command
   * queue dispatch, tracking blueprint, build helper, rally point, and originating
   * command state.
   */
  class CFactoryBuildTask : public CCommandTask
  {
  public:
    /**
     * Address: 0x005F9EB0 (FUN_005F9EB0, Moho::CFactoryBuildTask::CFactoryBuildTask)
     *
     * What it does:
     * Initializes one detached factory-build task with empty dispatch, blueprint,
     * helper, rally-point, and command lanes.
     */
    CFactoryBuildTask();

    /**
     * Address: 0x005F9F20 (FUN_005F9F20)
     * Mangled: ??0CFactoryBuildTask@Moho@@QAE@@Z_0
     *
     * IDA signature:
     * Moho::CFactoryBuildTask *__thiscall Moho::CFactoryBuildTask::CFactoryBuildTask(
     *   Moho::IAiCommandDispatchImpl *dispatch, Moho::CFactoryBuildTask *this,
     *   Moho::REntityBlueprint *bp, Moho::CUnitCommand *cmd, int rallyUnit);
     *
     * What it does:
     * Initializes one dispatch-bound factory build task, linking blueprint,
     * rally point unit weak pointer, and originating command weak pointer.
     */
    CFactoryBuildTask(CCommandTask* dispatchTask, const RUnitBlueprint* blueprint,
                      CUnitCommand* command, Unit* rallyPointUnit);

    /**
     * Address: 0x005FA010 (FUN_005FA010, non-deleting destructor body)
     * Thunk entry: 0x005FA110 (FUN_005FA110, scalar deleting destructor thunk)
     *
     * VFTable SLOT: 0
     */
    ~CFactoryBuildTask() override;

    /**
     * Address: 0x005FA790 (FUN_005FA790, Moho::CFactoryBuildTask::Execute)
     *
     * VFTable SLOT: 1
     *
     * What it does:
     * Drives the factory build task state machine: spawns target unit,
     * links build focus, and advances helper work-progress.
     */
    int Execute() override;

    /**
     * Address: 0x005FF020 (FUN_005FF020, Moho::CFactoryBuildTask::MemberDeserialize)
     *
     * What it does:
     * Deserializes the factory-build task lanes in binary order: command-task
     * base, dispatch pointer, blueprint pointer, helper, rally unit, counters,
     * and command weak lane.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005FF160 (FUN_005FF160, Moho::CFactoryBuildTask::MemberSerialize)
     *
     * What it does:
     * Serializes the factory-build task lanes in binary order: command-task
     * base, dispatch pointer, blueprint pointer, helper, rally unit, counters,
     * and command weak lane.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x005FAD00 (FUN_005FAD00, ??2CFactoryBuildTask@Moho@@QAE@@Z_0)
     *
     * What it does:
     * Allocates one `CFactoryBuildTask` and runs dispatch-bound construction.
     */
    [[nodiscard]] static CFactoryBuildTask* Create(
      CCommandTask* dispatchTask, const RUnitBlueprint* blueprint,
      CUnitCommand* command, Unit* rallyPointUnit);

    /**
     * Address: 0x005FA550 (FUN_005FA550, Moho::CFactoryBuildTask::InheritCommandsTo)
     *
     * What it does:
     * Transfers pending build commands from factory to the newly built unit.
     */
    void InheritCommandsTo(Unit* builtUnit);

  public:
    IAiCommandDispatchImpl* mDispatch;   // 0x30
    const RUnitBlueprint* mBlueprint;    // 0x34
    CBuildTaskHelper mBuildHelper;        // 0x38  (0x44 bytes, ends at 0x7C)
    WeakPtr<Unit> mRallyPointUnit;       // 0x7C  (0x08 bytes)
    std::int32_t mBuildCount;            // 0x84
    bool mHasCommand;                    // 0x88
    std::uint8_t mPad89[3];              // 0x89
    WeakPtr<CUnitCommand> mCommand;      // 0x8C  (0x08 bytes)
  };

  static_assert(sizeof(CFactoryBuildTask) == 0x94, "CFactoryBuildTask size must be 0x94");
  static_assert(
    offsetof(CFactoryBuildTask, mDispatch) == 0x30, "CFactoryBuildTask::mDispatch offset must be 0x30"
  );
  static_assert(
    offsetof(CFactoryBuildTask, mBlueprint) == 0x34, "CFactoryBuildTask::mBlueprint offset must be 0x34"
  );
  static_assert(
    offsetof(CFactoryBuildTask, mBuildHelper) == 0x38, "CFactoryBuildTask::mBuildHelper offset must be 0x38"
  );
  static_assert(
    offsetof(CFactoryBuildTask, mRallyPointUnit) == 0x7C,
    "CFactoryBuildTask::mRallyPointUnit offset must be 0x7C"
  );
  static_assert(
    offsetof(CFactoryBuildTask, mBuildCount) == 0x84, "CFactoryBuildTask::mBuildCount offset must be 0x84"
  );
  static_assert(
    offsetof(CFactoryBuildTask, mHasCommand) == 0x88, "CFactoryBuildTask::mHasCommand offset must be 0x88"
  );
  static_assert(
    offsetof(CFactoryBuildTask, mCommand) == 0x8C, "CFactoryBuildTask::mCommand offset must be 0x8C"
  );
} // namespace moho
