#pragma once
#include "wm3/Vector3.h"

namespace moho
{
  struct SPhysConstants
  {
    Wm3::Vec3f gravity;
  };

  static_assert(sizeof(SPhysConstants) == 0x0C, "SPhysConstants size must be 0x0C");
} // namespace moho
