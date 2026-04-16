#pragma once

#include "Wm3Vector2.h"

namespace moho
{
  using Vector2f = Wm3::Vector2f;

  /**
   * Address: 0x004CC8F0 (FUN_004CC8F0)
   *
   * What it does:
   * Returns Euclidean 2D distance between two Vector2f points.
   */
  [[nodiscard]] float Distance2D(const Wm3::Vector2f& from, const Wm3::Vector2f& to) noexcept;

  /**
   * Address: 0x004CC930 (FUN_004CC930)
   *
   * What it does:
   * Returns squared Euclidean 2D distance between two Vector2f points.
   */
  [[nodiscard]] float DistanceSquared2D(const Wm3::Vector2f& from, const Wm3::Vector2f& to) noexcept;

  /**
   * Address: 0x005657B0 (FUN_005657B0)
   *
   * What it does:
   * Returns true when both `x` and `y` lanes are not NaN.
   */
  [[nodiscard]] bool IsValidVector2f(const Wm3::Vector2f& value) noexcept;

  static_assert(sizeof(Vector2f) == 0x08, "moho::Vector2f size must be 0x08");
} // namespace moho
