#pragma once

#include "wm3/Vector2.h"

namespace moho
{
  using Vector2f = Wm3::Vector2f;

  static_assert(sizeof(Vector2f) == 0x08, "moho::Vector2f size must be 0x08");
} // namespace moho
