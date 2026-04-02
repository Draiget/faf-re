#pragma once

#include "Vector3.h"

namespace Wm3
{
  template <class T> struct Line3
  {
    Vector3<T> Origin{};
    Vector3<T> Direction{};

    /**
     * Address: 0x004741F0 (FUN_004741F0, Wm3::Line3f::Line3f)
     *
     * What it does:
     * Copies origin and direction vectors into a line object and returns `this`.
     */
    constexpr Line3(const Vector3<T>& origin, const Vector3<T>& direction) noexcept
      : Origin(origin)
      , Direction(direction)
    {}

    constexpr Line3() noexcept = default;
  };

  using Line3f = Line3<float>;
  using Line3d = Line3<double>;

  static_assert(sizeof(Line3f) == 0x18, "Line3f size must be 0x18");
} // namespace Wm3
