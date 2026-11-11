#include "editor/tools/EdPathing.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <deque>

namespace faf::editor
{
  namespace
  {
    constexpr float kHeightWordScale = 1.0f / 128.0f;
    constexpr float kNoWater = -10000.0f;
    constexpr std::uint8_t kLandSeabed = 0x1 | 0x2;
    constexpr std::uint8_t kWaterSubSeabed = 0x8 | 0x4 | 0x2;
  } // namespace

  std::vector<std::uint8_t> PassableCells(
    const std::uint16_t* const heights,
    const int width,
    const int height,
    const bool water,
    const float waterLevel,
    const PathFootprint& footprint
  )
  {
    const int cellsX = width - 1;
    const int cellsZ = height - 1;
    std::vector<std::uint8_t> cells(
      static_cast<std::size_t>(std::max(cellsX, 0)) * static_cast<std::size_t>(std::max(cellsZ, 0)), 0
    );
    if (heights == nullptr || cellsX <= 0 || cellsZ <= 0) {
      return cells;
    }
    const float level = water ? waterLevel : kNoWater;
    for (int z = 0; z < cellsZ; ++z) {
      const std::uint16_t* const row0 = heights + static_cast<std::size_t>(z) * static_cast<std::size_t>(width);
      const std::uint16_t* const row1 = row0 + width;
      for (int x = 0; x < cellsX; ++x) {
        const int h00 = row0[x];
        const int h10 = row0[x + 1];
        const int h01 = row1[x];
        const int h11 = row1[x + 1];
        const int low = std::min(std::min(h00, h10), std::min(h01, h11));
        const int high = std::max(std::max(h00, h10), std::max(h01, h11));
        std::uint8_t mask = footprint.caps;
        if (footprint.minWaterDepth > level - static_cast<float>(high) * kHeightWordScale) {
          mask = static_cast<std::uint8_t>(mask & ~kWaterSubSeabed);
        }
        if (level - static_cast<float>(low) * kHeightWordScale > footprint.maxWaterDepth) {
          mask = static_cast<std::uint8_t>(mask & ~kLandSeabed);
        }
        if ((mask & kLandSeabed) != 0 && footprint.maxSlope != 0.0f) {
          int delta = std::abs(h11 - h01);
          delta = std::max(delta, std::abs(h11 - h10));
          delta = std::max(delta, std::abs(h01 - h00));
          delta = std::max(delta, std::abs(h10 - h00));
          if (static_cast<float>(delta) * kHeightWordScale > footprint.maxSlope) {
            mask = static_cast<std::uint8_t>(mask & ~kLandSeabed);
          }
        }
        cells[static_cast<std::size_t>(z) * static_cast<std::size_t>(cellsX) + static_cast<std::size_t>(x)] =
          (mask & (kLandSeabed | kWaterSubSeabed)) != 0 ? 1 : 0;
      }
    }
    return cells;
  }

  int ConnectAreas(
    const std::vector<std::uint8_t>& cells,
    const int cellsX,
    const int cellsZ,
    std::vector<int>& areas
  )
  {
    areas.assign(cells.size(), 0);
    int count = 0;
    std::deque<int> queue;
    for (int start = 0; start < static_cast<int>(cells.size()); ++start) {
      if (cells[static_cast<std::size_t>(start)] == 0 || areas[static_cast<std::size_t>(start)] != 0) {
        continue;
      }
      ++count;
      areas[static_cast<std::size_t>(start)] = count;
      queue.push_back(start);
      while (!queue.empty()) {
        const int at = queue.front();
        queue.pop_front();
        const int x = at % cellsX;
        const int z = at / cellsX;
        const int next[4][2] = {{x - 1, z}, {x + 1, z}, {x, z - 1}, {x, z + 1}};
        for (const auto& n : next) {
          if (n[0] < 0 || n[1] < 0 || n[0] >= cellsX || n[1] >= cellsZ) {
            continue;
          }
          const int i = n[1] * cellsX + n[0];
          if (cells[static_cast<std::size_t>(i)] != 0 && areas[static_cast<std::size_t>(i)] == 0) {
            areas[static_cast<std::size_t>(i)] = count;
            queue.push_back(i);
          }
        }
      }
    }
    return count;
  }

  int AreaNear(
    const std::vector<int>& areas,
    const int cellsX,
    const int cellsZ,
    const float x,
    const float z,
    const int reach
  )
  {
    const int cx = static_cast<int>(std::floor(x));
    const int cz = static_cast<int>(std::floor(z));
    int best = 0;
    int bestDistance = reach * reach + 1;
    for (int dz = -reach; dz <= reach; ++dz) {
      for (int dx = -reach; dx <= reach; ++dx) {
        const int px = cx + dx;
        const int pz = cz + dz;
        if (px < 0 || pz < 0 || px >= cellsX || pz >= cellsZ) {
          continue;
        }
        const int area =
          areas[static_cast<std::size_t>(pz) * static_cast<std::size_t>(cellsX) + static_cast<std::size_t>(px)];
        if (area != 0 && dx * dx + dz * dz < bestDistance) {
          bestDistance = dx * dx + dz * dz;
          best = area;
        }
      }
    }
    return best;
  }
} // namespace faf::editor
