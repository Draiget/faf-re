#pragma once
#include "Wm3Vector3.h"

namespace moho
{
  struct GridPos
  {
    int x;
    int z;

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
