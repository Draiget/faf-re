#pragma once

#include "wm3/Vector3.h"

namespace moho
{
  using Vector3f = Wm3::Vector3f;

  static_assert(sizeof(Vector3f) == 0x0C, "moho::Vector3f size must be 0x0C");
} // namespace moho
