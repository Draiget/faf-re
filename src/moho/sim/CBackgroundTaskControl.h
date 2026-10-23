#pragma once

#include <cstddef>

namespace moho
{
  struct SWldScenarioLoadControl;

  /**
   * Address context:
   * - consumed by 0x00412C70 (FUN_00412C70, func_UpdateLoadingProgress)
   * - passed through map/terrain load paths (for example 0x008A1700 CWldTerrainRes::Load)
   *
   * What it does:
   * Thin progress-control handle passed through long-running load/update loops.
   * A null `mHandle` means "no progress callback".
   */
  struct CBackgroundTaskControl
  {
    SWldScenarioLoadControl* mHandle; // +0x00
  };

  static_assert(offsetof(CBackgroundTaskControl, mHandle) == 0x00, "CBackgroundTaskControl::mHandle offset must be 0x00");
  static_assert(sizeof(CBackgroundTaskControl) == 0x04, "CBackgroundTaskControl size must be 0x04");
} // namespace moho
