// The map editor's terrain types (src/editor/tools/EdTerrainTypes.cpp): the game's TerrainTypes.lua read, a map's type
// grid painted and drawn as runs.

#include "editor/tools/EdTerrainTypes.h"

#include <gtest/gtest.h>

namespace
{
  // The shape of the game's TerrainTypes.lua entries (fields in varying order, effect tables between them).
  const char* const kLua = R"(
TerrainTypes = {
    {
        Name = 'Default',
        TypeCode = 1,
        Color = '00000000',
        Description = 'Default',
        Style = 'Default',
        Blocking = false,
        FXIdle = { Land = { Radar01 = { EmitterBasePath .. 'radar_ambient_01_emit.bp', }, }, },
    },
    {
        Name = 'Vegetation02',
        TypeCode = 81,
        Description = 'Rocky grass',
        Color = 'FF00FFFF',
        Style = 'Evergreen',
    },
    {
        Name = 'Lava01',
        TypeCode = 230,
        Color = 'FFCC2254',
        Description = 'Lava',
        Style = 'Lava',
        Blocking = true,
    },
}
)";

  TEST(
    TerrainTypes,
    ReadsTheGamesTable
  )
  {
    const std::vector<faf::editor::TerrainTypeInfo> types = faf::editor::ParseTerrainTypes(kLua);
    ASSERT_EQ(types.size(), 3u);
    EXPECT_EQ(types[1].code, 81);
    EXPECT_EQ(types[1].description, "Rocky grass");
    EXPECT_EQ(types[1].color, 0xFF00FFFFu);
    EXPECT_EQ(types[1].style, "Evergreen");
    EXPECT_FALSE(types[1].blocking);
    EXPECT_TRUE(types[2].blocking);
    EXPECT_EQ(types[0].color, 0u);
  }

  TEST(
    TerrainTypes,
    PaintsADiscAndDrawsRuns
  )
  {
    const int size = 16;
    std::vector<std::uint8_t> grid(size * size, 1);
    // Radius 2 around (8, 8): the 12 cells whose centres are within 2.
    EXPECT_EQ(faf::editor::PaintTerrainType(grid.data(), size, size, 8.0f, 8.0f, 2.0f, 81), 12);
    EXPECT_EQ(faf::editor::PaintTerrainType(grid.data(), size, size, 8.0f, 8.0f, 2.0f, 81), 0);
    EXPECT_EQ(grid[8 * size + 8], 81);
    EXPECT_EQ(grid[8 * size + 10], 1);
    const std::vector<faf::editor::TerrainTypeRun> runs = faf::editor::TerrainTypeRuns(grid.data(), size, size);
    int cells = 0;
    for (const faf::editor::TerrainTypeRun& run : runs) {
      EXPECT_EQ(run.code, 81);
      cells += run.x1 - run.x0;
    }
    EXPECT_EQ(cells, 12);
    EXPECT_EQ(runs.size(), 4u);
    // Off the map's edge nothing outside is touched.
    EXPECT_GT(faf::editor::PaintTerrainType(grid.data(), size, size, 0.0f, 0.0f, 3.0f, 230), 0);
    EXPECT_EQ(grid[0], 230);
  }
} // namespace
