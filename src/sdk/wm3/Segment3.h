#pragma once

#include "Vector3.h"

namespace Wm3
{
  /**
   * Segment represented as Origin + t*Direction, where t is in [-Extent, +Extent].
   * This matches the WildMagic/FA binary-facing layout used by Dist/Intr helpers.
   */
  template <class T> struct Segment3
  {
    Vector3<T> Origin{};
    Vector3<T> Direction{};
    T Extent{};
  };

  using Segment3f = Segment3<float>;
  using Segment3d = Segment3<double>;

  static_assert(sizeof(Segment3f) == 0x1C, "Segment3f size must be 0x1C");
} // namespace Wm3
