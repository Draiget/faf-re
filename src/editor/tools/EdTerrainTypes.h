#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace faf::editor
{
  /** A terrain type from the game's `/lua/TerrainTypes.lua`: the byte a map's cell holds (its TypeCode) and its look. */
  struct TerrainTypeInfo
  {
    int code = 1;
    std::string name;
    std::string description;
    std::string style;
    /** ARGB, as the file's `Color` writes it (`FF00FFFF`). */
    std::uint32_t color = 0;
    /** The type the sim treats as blocking (lava): units don't path over it. */
    bool blocking = false;
  };

  /** The types of a TerrainTypes.lua text, in the file's order (each entry's fields read up to the next entry). */
  std::vector<TerrainTypeInfo> ParseTerrainTypes(const std::string& lua);

  /** A row of cells of one type, for drawing: cells x0 to x1 (exclusive) of row z. */
  struct TerrainTypeRun
  {
    int x0 = 0;
    int x1 = 0;
    int z = 0;
    std::uint8_t code = 0;
  };

  /** The grid (`width` x `height` cells, row by row) as runs, the `skip` type (Default, 1) left out. */
  std::vector<TerrainTypeRun> TerrainTypeRuns(const std::uint8_t* grid, int width, int height, std::uint8_t skip = 1);

  /** Sets the cells whose centres lie within `radius` of (x, z) to `code`; returns how many changed. */
  int PaintTerrainType(std::uint8_t* grid, int width, int height, float x, float z, float radius, std::uint8_t code);
} // namespace faf::editor
