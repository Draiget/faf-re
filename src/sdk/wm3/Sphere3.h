#pragma once

#include "Vector3.h"

namespace Wm3
{
  template <class T> struct Sphere3
  {
    Vector3<T> Center{};
    T Radius{};

    constexpr Sphere3() = default;
    constexpr Sphere3(const Vector3<T>& center, const T radius) noexcept :
        Center(center),
        Radius(radius)
    {}
  };

  using Sphere3f = Sphere3<float>;

  static_assert(sizeof(Sphere3f) == 0x10, "Sphere3f size must be 0x10");
} // namespace Wm3
