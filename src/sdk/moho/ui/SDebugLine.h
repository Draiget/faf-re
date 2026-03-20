#pragma once
#include "moho/unit/core/Unit.h"

namespace moho
{
  struct SDebugLine
  {
    Wm3::Vec3f p0;
    Wm3::Vec3f p1;
    int32_t depth0;
    int32_t depth1;
  };
  static_assert(sizeof(SDebugLine) == 0x20, "SDebugLine size must be == 0x20");
} // namespace moho
