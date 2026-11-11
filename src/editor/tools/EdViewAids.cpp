#include "editor/tools/EdViewAids.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>

namespace faf::editor
{
  float CellSlope(
    const std::uint16_t* const heights,
    const int width,
    const int x,
    const int z,
    const float heightScale
  )
  {
    const std::uint16_t* const row0 = heights + static_cast<std::size_t>(z) * static_cast<std::size_t>(width);
    const std::uint16_t* const row1 = row0 + width;
    const int h00 = row0[x], h10 = row0[x + 1], h01 = row1[x], h11 = row1[x + 1];
    int delta = std::abs(h11 - h01);
    delta = std::max(delta, std::abs(h11 - h10));
    delta = std::max(delta, std::abs(h01 - h00));
    delta = std::max(delta, std::abs(h10 - h00));
    return static_cast<float>(delta) * heightScale;
  }

  std::vector<std::uint8_t> SlopeBands(
    const std::uint16_t* const heights,
    const int width,
    const int height,
    const float heightScale
  )
  {
    std::vector<std::uint8_t> bands;
    if (heights == nullptr || width < 2 || height < 2) {
      return bands;
    }
    const int cellsX = width - 1;
    const int cellsZ = height - 1;
    bands.resize(static_cast<std::size_t>(cellsX) * static_cast<std::size_t>(cellsZ));
    for (int z = 0; z < cellsZ; ++z) {
      for (int x = 0; x < cellsX; ++x) {
        const float slope = CellSlope(heights, width, x, z, heightScale);
        bands[static_cast<std::size_t>(z) * static_cast<std::size_t>(cellsX) + static_cast<std::size_t>(x)] =
          slope > 0.75f   ? 3
          : slope > 0.5f  ? 2
          : slope > 0.25f ? 1
                          : 0;
      }
    }
    return bands;
  }

  std::string DistanceText(
    const float units
  )
  {
    char text[64];
    (void)std::snprintf(
      text, sizeof(text), "%.1f units, %.2f km", static_cast<double>(units), static_cast<double>(units / kUnitsPerKm)
    );
    return text;
  }
} // namespace faf::editor
