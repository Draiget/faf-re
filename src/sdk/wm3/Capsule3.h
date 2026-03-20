#pragma once

#include "Segment3.h"

namespace Wm3
{
  template <class T> struct Capsule3
  {
    Segment3<T> Segment{};
    T Radius{};
  };

  using Capsule3f = Capsule3<float>;
  using Capsule3d = Capsule3<double>;

  static_assert(sizeof(Capsule3f) == 0x20, "Capsule3f size must be 0x20");
} // namespace Wm3
