#pragma once

#include "moho/sim/CWldMap.h"

namespace moho
{
  /**
   * Legacy compatibility aliases:
   * - session visibility query interface owner is `CWldMap`.
   * - slot 62 query method is `IWldTerrainRes::GetPlayableMapRect`.
   */
  using SessionVisibilityQuery = IWldTerrainRes;
  using SessionVisibilityQueryRoot = CWldMap;
} // namespace moho
