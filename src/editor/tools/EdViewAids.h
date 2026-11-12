#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace faf::editor
{
  /** Game units in a kilometre on the game's scale (a 20 km map is 1024 units). */
  constexpr float kUnitsPerKm = 51.2f;

  /**
   * A cell's slope as the game's pathing reads it (STIMap::OccupancyCapsOfFootprintAt 0x00564DF0): the largest rise
   * along one of its four edges, in game units.
   */
  float CellSlope(const std::uint16_t* heights, int width, int x, int z, float heightScale);

  /**
   * One byte a cell ((width - 1) x (height - 1) cells between the samples): 0 below 0.25 (flat enough to build on),
   * 1 to 0.5, 2 to 0.75, 3 above 0.75 (steeper than most land units' MaxSlope).
   */
  std::vector<std::uint8_t> SlopeBands(const std::uint16_t* heights, int width, int height, float heightScale);

  /** "123.4 units, 2.41 km" for a measured distance. */
  std::string DistanceText(float units);
} // namespace faf::editor
