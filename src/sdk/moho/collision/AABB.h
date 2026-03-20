#pragma once

#include "wm3/AABB.h"

namespace moho
{
  using AABB = Wm3::AxisAlignedBox3f;
  static_assert(sizeof(AABB) == 0x18, "moho::AABB size must be 0x18");
} // namespace moho
