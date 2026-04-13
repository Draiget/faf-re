#pragma once

#include <cstddef>

namespace moho
{
  /**
   * Minimal recovered layout owner for `CUnitGuardTask` type lanes.
   */
  class CUnitGuardTask
  {
  public:
    /**
     * Address: 0x006110F0 (FUN_006110F0, Moho::CUnitGuardTask::CUnitGuardTask)
     *
     * What it does:
     * Constructs one guard-task instance in place.
     */
    CUnitGuardTask();

  private:
    unsigned char mPadding[0xC0];
  };

  static_assert(sizeof(CUnitGuardTask) == 0xC0, "CUnitGuardTask size must be 0xC0");
} // namespace moho

