#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace faf::editor
{
  /** A terrain type from the game's `/lua/TerrainTypes.lua`: the byte a map's cell holds (its TypeCode) and its look.
   */
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

  /**
   * The terrain type a layer texture gets by default (FAF Studio's terraintype.lua RULES): the first word of a list
   * found in its file name (lava 230, snow 200, ice 201, wet sand 41, sand 40, tarmac 151, grass 80, rock 150, cliff
   * 158, gravel 4, dirt 2, mud 3 ...), when `types` has that code; 1 (Default) otherwise.
   */
  [[nodiscard]] int DefaultTerrainTypeFor(const std::string& albedo, const std::vector<TerrainTypeInfo>& types);

  /**
   * The terrain types from the texture layers: each type cell (`gridWidth` x `gridHeight`, over the same map as the
   * masks) takes the type of the layer seen most at its middle: a painted layer's share is its mask weight (in the
   * shader's range: `remapped`, RemappedStrata's bits) times what the layers above leave free, the base layer's what
   * nothing covers. `types[layer]` (0 the base, 1..8); layers without a texture (`textured`) show nothing.
   * `onlyDefault` leaves cells that have a type other than Default (1). Returns how many cells changed.
   */
  std::size_t TerrainTypesFromLayers(
    const std::uint64_t* texels,
    int maskWidth,
    int maskHeight,
    std::uint8_t remapped,
    const std::array<bool, 9>& textured,
    const std::array<int, 9>& types,
    std::uint8_t* grid,
    int gridWidth,
    int gridHeight,
    bool onlyDefault
  );
} // namespace faf::editor
