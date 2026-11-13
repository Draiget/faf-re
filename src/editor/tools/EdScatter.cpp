#include "editor/tools/EdScatter.h"

#include <algorithm>
#include <cmath>
#include <unordered_map>

namespace faf::editor
{
  namespace
  {
    /** A cell's own random numbers: a hash of its place and the seed (no state, so the order of cells doesn't matter).
     */
    float Hash01(
      const std::int64_t i,
      const std::int64_t j,
      const std::uint32_t seed,
      const std::uint32_t salt
    )
    {
      std::uint64_t h = static_cast<std::uint64_t>(i) * 0x9E3779B97F4A7C15ULL ^
        static_cast<std::uint64_t>(j) * 0xC2B2AE3D27D4EB4FULL ^ (static_cast<std::uint64_t>(seed) << 32) ^ salt;
      h ^= h >> 33;
      h *= 0xFF51AFD7ED558CCDULL;
      h ^= h >> 33;
      h *= 0xC4CEB9FE1A85EC53ULL;
      h ^= h >> 33;
      return static_cast<float>(h >> 40) / 16777216.0f;
    }
  } // namespace

  std::vector<std::pair<float, float>> ScatterPoints(
    const ScatterOptions& options,
    const std::function<bool(float x, float z)>& accept
  )
  {
    std::vector<std::pair<float, float>> points;
    const float spacing = std::max(0.5f, options.spacing);
    const float x0 = std::min(options.x0, options.x1), x1 = std::max(options.x0, options.x1);
    const float z0 = std::min(options.z0, options.z1), z1 = std::max(options.z0, options.z1);
    if (!(x1 > x0) || !(z1 > z0) || !(options.density > 0.0f)) {
      return points;
    }
    const float chance = std::min(1.0f, options.density * spacing * spacing / 10000.0f);
    const auto columns = static_cast<std::int64_t>(std::ceil((x1 - x0) / spacing));
    const auto rows = static_cast<std::int64_t>(std::ceil((z1 - z0) / spacing));
    // The kept points by their cell, for the spacing check against the eight cells around.
    std::unordered_map<std::int64_t, std::vector<std::size_t>> kept;
    const auto key = [columns](const std::int64_t i, const std::int64_t j) {
      return j * (columns + 2) + i;
    };
    for (std::int64_t j = 0; j < rows; ++j) {
      for (std::int64_t i = 0; i < columns; ++i) {
        if (Hash01(i, j, options.seed, 1U) >= chance) {
          continue;
        }
        const float x = x0 + (static_cast<float>(i) + Hash01(i, j, options.seed, 2U)) * spacing;
        const float z = z0 + (static_cast<float>(j) + Hash01(i, j, options.seed, 3U)) * spacing;
        if (x > x1 || z > z1) {
          continue;
        }
        bool near = false;
        for (std::int64_t dj = -1; dj <= 1 && !near; ++dj) {
          for (std::int64_t di = -1; di <= 1 && !near; ++di) {
            const auto found = kept.find(key(i + di, j + dj));
            if (found == kept.end()) {
              continue;
            }
            for (const std::size_t k : found->second) {
              if (std::hypot(points[k].first - x, points[k].second - z) < spacing) {
                near = true;
                break;
              }
            }
          }
        }
        if (near || !accept(x, z)) {
          continue;
        }
        kept[key(i, j)].push_back(points.size());
        points.emplace_back(x, z);
        if (static_cast<int>(points.size()) >= options.limit) {
          return points;
        }
      }
    }
    return points;
  }

  float SlopeDegrees(
    const float left,
    const float right,
    const float above,
    const float below
  )
  {
    const float dx = (right - left) * 0.5f;
    const float dz = (below - above) * 0.5f;
    return std::atan(std::hypot(dx, dz)) * (180.0f / 3.14159265f);
  }
} // namespace faf::editor
