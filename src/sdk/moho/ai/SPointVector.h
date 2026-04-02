#pragma once

#include <cstddef>

#include "wm3/Vector3.h"

namespace moho
{
  struct SPointVector
  {
    Wm3::Vector3<float> point;  // +0x00
    Wm3::Vector3<float> vector; // +0x0C
  };

  static_assert(offsetof(SPointVector, point) == 0x00, "SPointVector::point offset must be 0x00");
  static_assert(offsetof(SPointVector, vector) == 0x0C, "SPointVector::vector offset must be 0x0C");
  static_assert(sizeof(SPointVector) == 0x18, "SPointVector size must be 0x18");
} // namespace moho
