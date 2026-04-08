#include "GridPos.h"

#include <cmath>

namespace
{
  [[nodiscard]] int ComputeGridCellCoordinate(const float worldCoordinate, const int gridSize) noexcept
  {
    const float reciprocal = 1.0f / static_cast<float>(gridSize);
    const float scaled = worldCoordinate * reciprocal;

    // Binary shape: frndint + conditional -1 adjust when source < rounded.
    const double rounded = std::nearbyint(static_cast<double>(scaled));
    return static_cast<int>(rounded) + ((scaled < rounded) ? -1 : 0);
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
} // namespace moho
