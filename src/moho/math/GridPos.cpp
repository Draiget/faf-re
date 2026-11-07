#include "GridPos.h"

#include <cmath>
#include <cstdint>

#include "legacy/math/X87Math.h"

namespace
{
  [[nodiscard]] int ComputeGridCellCoordinate(const float worldCoordinate, const int gridSize) noexcept
  {
    const float reciprocal = 1.0f / static_cast<float>(gridSize);
    return fa::FloorToIntX87(worldCoordinate * reciprocal);
  }

} // namespace

namespace moho
{
  /**
   * Address: 0x00506E20 (FUN_00506E20, ??0GridPos@Moho@@QAE@@Z)
   *
   * Wm3::Vector3f* wldPos, int gridSize
   *
   * What it does:
   * Converts world-space x/z lanes into integer grid coordinates with the
   * original reciprocal-scale and frndint-adjusted floor semantics.
   */
  GridPos::GridPos(Wm3::Vec3f* const wldPos, const int gridSize) noexcept
    : x(ComputeGridCellCoordinate(wldPos->x, gridSize))
    , z(ComputeGridCellCoordinate(wldPos->z, gridSize))
  {
  }

  int FloorSecondsToTicks(const float seconds) noexcept
  {
    return fa::FloorToIntX87(seconds * 10.0f);
  }
} // namespace moho
