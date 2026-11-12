#pragma once

#include <cstdint>
#include <vector>

namespace faf::editor
{
  /** The footprint numbers a unit's pathing goes by (SFootprint: occupancy caps, MaxSlope, Min/MaxWaterDepth). */
  struct PathFootprint
  {
    /** EOccupancyCaps bits: land 0x1, seabed 0x2, sub 0x4, water 0x8. */
    std::uint8_t caps = 0x1;
    float maxSlope = 0.0f;
    float minWaterDepth = 0.0f;
    float maxWaterDepth = 0.0f;
  };

  /**
   * One byte a cell ((width - 1) x (height - 1) cells between the samples): 1 where the footprint can stand, as
   * STIMap::OccupancyCapsOfFootprintAt (0x00564DF0) decides from the heights and the sea: water and sub out when the
   * water over the cell's highest corner is shallower than MinWaterDepth; land and seabed out when the water over its
   * lowest corner is deeper than MaxWaterDepth, or when an edge of the cell rises more than MaxSlope. Without a sea
   * the level is -10000. The terrain types' own blocking is not counted.
   */
  std::vector<std::uint8_t> PassableCells(
    const std::uint16_t* heights,
    int width,
    int height,
    bool water,
    float waterLevel,
    const PathFootprint& footprint
  );

  /** Joins passable cells edge to edge: an area number per cell (0 where blocked); returns how many areas. */
  int ConnectAreas(const std::vector<std::uint8_t>& cells, int cellsX, int cellsZ, std::vector<int>& areas);

  /** The area of the passable cell nearest (x, z) within `reach` cells (a resource on a slope is reached beside it), or
   * 0. */
  int AreaNear(const std::vector<int>& areas, int cellsX, int cellsZ, float x, float z, int reach);
} // namespace faf::editor
