#pragma once

#include <cstddef>

namespace moho
{
  class CCommandTask;
  class CUnitCommand;

  /**
   * Runtime owner for ferry task command lanes.
   */
  class CUnitFerryTask
  {
  public:
    /**
     * Address: 0x0060DFC0 (FUN_0060DFC0, Moho::CUnitFerryTask::CUnitFerryTask)
     *
     * What it does:
     * Initializes one ferry-task lane from parent command-task and command
     * payload context.
     */
    CUnitFerryTask(CCommandTask* parentTask, CUnitCommand* command);

    /**
     * Address: 0x0060F7E0 (FUN_0060F7E0, Moho::CUnitFerryTask::operator new)
     *
     * What it does:
     * Allocates one ferry-task object and forwards constructor arguments into
     * in-place construction.
     */
    [[nodiscard]] static CUnitFerryTask* Create(CCommandTask* parentTask, CUnitCommand* command);

  private:
    unsigned char mPadding[0x60];
  };

  static_assert(sizeof(CUnitFerryTask) == 0x60, "CUnitFerryTask size must be 0x60");
} // namespace moho
