#pragma once

#include <cstdint>
#include <functional>
#include <utility>
#include <vector>

namespace faf::editor
{
  /**
   * Map-wide scatter (the Props tool's Fill the map): points over a rectangle at a density, none closer than a spacing,
   * each kept only if `accept` says so (the symmetry's first part, dry and flat enough ground). The caller places one
   * object at each and its mirrored copies, so the copies match: the points are drawn once, not per copy.
   */
  struct ScatterOptions
  {
    float x0 = 0.0f, z0 = 0.0f, x1 = 0.0f, z1 = 0.0f; // the rectangle
    float density = 10.0f;                            // points per 100 x 100 units, before `accept` and the spacing
    float spacing = 4.0f;                             // the least distance between two points
    std::uint32_t seed = 1;
    int limit = 20000; // never more points than this
  };

  /**
   * One candidate in each spacing-sized cell, kept with the chance the density gives, at a random place in it, then
   * dropped when nearer than the spacing to a point already kept or when `accept` refuses it. The same options give the
   * same points.
   */
  [[nodiscard]] std::vector<std::pair<float, float>>
  ScatterPoints(const ScatterOptions& options, const std::function<bool(float x, float z)>& accept);

  /** The ground's slope in degrees from the heights a unit either side (dx = right - left, dz = below - above). */
  [[nodiscard]] float SlopeDegrees(float left, float right, float above, float below);
} // namespace faf::editor
