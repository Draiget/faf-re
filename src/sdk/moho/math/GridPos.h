#pragma once
#include "Wm3Vector3.h"

namespace moho
{
  struct GridPos
  {
    int x;
    int z;

    /**
     * Declaring the world-position converting constructor below suppresses the
     * implicit default constructor and makes `GridPos` a non-aggregate, so a
     * brace-init such as `GridPos p{0, 0}` stops meaning "x = 0, z = 0" and
     * silently resolves to that constructor with a NULL `wldPos`. Restore the
     * default constructor so `GridPos p{}` value-initialises both lanes.
     */
    GridPos() noexcept = default;

    /**
     * Address: 0x00506E20 (FUN_00506E20, ??0GridPos@Moho@@QAE@@Z)
     *
     * Wm3::Vector3f* wldPos, int gridSize
     *
     * What it does:
     * Converts world `x/z` into integer grid-cell indices using reciprocal
     * scale plus the binary's frndint-and-adjust floor lane.
     */
    GridPos(Wm3::Vec3f* wldPos, int gridSize) noexcept;
  };

  /**
   * Address: 0x0066D1D0 (FUN_0066D1D0)
   *
   * What it does:
   * Multiplies one seconds value by `10.0f`, applies the legacy x87
   * `frndint` floor adjustment lane, and returns the integer tick count.
   */
  [[nodiscard]] int FloorSecondsToTicks(float seconds) noexcept;
} // namespace moho
