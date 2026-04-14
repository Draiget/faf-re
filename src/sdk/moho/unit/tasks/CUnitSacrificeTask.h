#pragma once

#include <cstddef>

namespace moho
{
  class CCommandTask;
  class CUnitCommand;

  /**
   * Runtime owner for unit-sacrifice command task state.
   */
  class CUnitSacrificeTask
  {
  public:
    /**
     * Address: 0x005FAD90 (FUN_005FAD90, Moho::CUnitSacrificeTask::CUnitSacrificeTask)
     *
     * What it does:
     * Initializes one sacrifice-task lane from parent command-task and command
     * payload ownership context.
     */
    CUnitSacrificeTask(CCommandTask* parentTask, CUnitCommand* command);

    /**
     * Address: 0x005FB8B0 (FUN_005FB8B0, Moho::CUnitSacrificeTask::operator new)
     *
     * What it does:
     * Allocates one sacrifice-task object and forwards constructor arguments
     * into in-place construction.
     */
    [[nodiscard]] static CUnitSacrificeTask* Create(CCommandTask* parentTask, CUnitCommand* command);

  private:
    unsigned char mPadding[0x4C];
  };

  static_assert(sizeof(CUnitSacrificeTask) == 0x4C, "CUnitSacrificeTask size must be 0x4C");
} // namespace moho
