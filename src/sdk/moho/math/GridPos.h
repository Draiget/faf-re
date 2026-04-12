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
} // namespace moho
