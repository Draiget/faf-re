#pragma once

#include <cstddef>

namespace moho
{
  /**
   * Minimal recovered layout owner for `CUnitCaptureTask` type lanes.
   */
  class CUnitCaptureTask
  {
  public:
    /**
     * Address: 0x00603F40 (FUN_00603F40, Moho::CUnitCaptureTask::CUnitCaptureTask)
     *
     * What it does:
     * Constructs one capture-task instance in place.
     */
    CUnitCaptureTask();

  private:
    unsigned char mPadding[0x64];
  };

  static_assert(sizeof(CUnitCaptureTask) == 0x64, "CUnitCaptureTask size must be 0x64");
} // namespace moho

