#pragma once

#include <cstddef>

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
  struct RUnitBlueprint;

  class CUnitUpgradeTask : public CCommandTask
  {
  public:
    /**
     * Address: 0x005FEBC0 (FUN_005FEBC0)
     *
     * What it does:
     * Deserializes upgrade-task runtime state (base command-task lane, target
     * blueprint pointer, build-helper lane, and upgraded-unit weak pointer).
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005FEC90 (FUN_005FEC90)
     *
     * What it does:
     * Serializes upgrade-task runtime state (base command-task lane, target
     * blueprint pointer, build-helper lane, and upgraded-unit weak pointer).
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x005F83D0 (FUN_005F83D0, ??0CUnitUpgradeTask@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes detached upgrade-task storage with empty build-helper/focus
     * state for serializer/typeinfo constructor lanes.
     */
    CUnitUpgradeTask();

    /**
     * Address: 0x005F8420 (FUN_005F8420, ??0CUnitUpgradeTask@Moho@@QAE@@Z_0)
     *
     * What it does:
     * Initializes one dispatch-bound upgrade task and marks owner unit
     * upgrading/work-progress lanes.
     */
    CUnitUpgradeTask(CCommandTask* dispatchTask, const RUnitBlueprint* toBlueprint);

    /**
     * Address: 0x005F84C0 (FUN_005F84C0, ??1CUnitUpgradeTask@Moho@@QAE@@Z)
     *
     * What it does:
     * Stops upgrade build lanes, restores owner state bits, and commits
     * dispatch result codes for interrupt/complete paths.
     */
    ~CUnitUpgradeTask() override;

    /**
     * Address: 0x005F8890 (FUN_005F8890, Moho::CUnitUpgradeTask::TaskTick)
     *
     * What it does:
     * Runs the upgrade task state machine: spawns target unit, links build
     * focus, and advances helper work-progress.
     */
    [[nodiscard]] int TaskTick();

    int Execute() override;

    /**
     * Address: 0x005F8B80 (FUN_005F8B80, ??2CUnitUpgradeTask@Moho@@QAE@@Z_0)
     *
     * What it does:
     * Allocates one `CUnitUpgradeTask` and runs dispatch-bound construction.
     */
    [[nodiscard]] static CUnitUpgradeTask* Create(CCommandTask* dispatchTask, const RUnitBlueprint* toBlueprint);

  public:
    const RUnitBlueprint* mToBlueprint; // 0x30
    CBuildTaskHelper mBuildHelper;      // 0x34
    WeakPtr<Unit> mUpgradedUnit;        // 0x78
  };

  static_assert(sizeof(CUnitUpgradeTask) == 0x80, "CUnitUpgradeTask size must be 0x80");
  static_assert(
    offsetof(CUnitUpgradeTask, mToBlueprint) == 0x30, "CUnitUpgradeTask::mToBlueprint offset must be 0x30"
  );
  static_assert(
    offsetof(CUnitUpgradeTask, mBuildHelper) == 0x34, "CUnitUpgradeTask::mBuildHelper offset must be 0x34"
  );
  static_assert(
    offsetof(CUnitUpgradeTask, mUpgradedUnit) == 0x78, "CUnitUpgradeTask::mUpgradedUnit offset must be 0x78"
  );
} // namespace moho
