#include "Vector2f.h"

#include <cmath>

namespace moho
{
  /**
   * Address: 0x004CC930 (FUN_004CC930)
   *
   * What it does:
   * Returns squared Euclidean 2D distance between two Vector2f points.
   */
  float DistanceSquared2D(const Wm3::Vector2f& from, const Wm3::Vector2f& to) noexcept
  {
    const float dx = to.x - from.x;
    const float dy = to.y - from.y;
    return (dx * dx) + (dy * dy);
  }

  /**
   * Address: 0x004CC8F0 (FUN_004CC8F0)
   *
   * What it does:
   * Returns Euclidean 2D distance between two Vector2f points.
   */
  float Distance2D(const Wm3::Vector2f& from, const Wm3::Vector2f& to) noexcept
  {
    return std::sqrt(DistanceSquared2D(from, to));
  }
} // namespace moho
