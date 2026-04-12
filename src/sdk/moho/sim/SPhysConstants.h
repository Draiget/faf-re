#pragma once

#include "Wm3Vector3.h"

namespace moho
{
  struct SPhysConstants
  {
    Wm3::Vec3f mGravity;
  };

  static_assert(sizeof(SPhysConstants) == 0x0C, "SPhysConstants size must be 0x0C");
} // namespace moho
