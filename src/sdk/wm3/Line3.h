#pragma once

#include "Vector3.h"

namespace Wm3
{
  template <class T> struct Line3
  {
    Vector3<T> Origin{};
    Vector3<T> Direction{};
  };

  using Line3f = Line3<float>;
  using Line3d = Line3<double>;

  static_assert(sizeof(Line3f) == 0x18, "Line3f size must be 0x18");
} // namespace Wm3
