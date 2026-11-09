// The map editor's pathing (src/editor/tools/EdPathing.cpp): cells a footprint can stand on, as the sim's
// OccupancyCapsOfFootprintAt decides from slope and water depth, and the areas they join into.

#include "editor/tools/EdPathing.h"

#include <gtest/gtest.h>

namespace
{
  // 9 x 9 samples (8 x 8 cells): flat at 10 units, a wall of 20 units along x = 4.
  std::vector<std::uint16_t> Field()
  {
    std::vector<std::uint16_t> heights(81, static_cast<std::uint16_t>(10 * 128));
    for (int z = 0; z < 9; ++z) {
      heights[static_cast<std::size_t>(z) * 9 + 4] = static_cast<std::uint16_t>(30 * 128);
    }
    return heights;
  }

  TEST(Pathing, ASteepWallSplitsTheLand)
  {
    const std::vector<std::uint16_t> heights = Field();
    faf::editor::PathFootprint tank;
    tank.caps = 0x1;
    tank.maxSlope = 0.75f;
    const std::vector<std::uint8_t> cells = faf::editor::PassableCells(heights.data(), 9, 9, false, 0.0f, tank);
    ASSERT_EQ(cells.size(), 64u);
    // The cells touching the wall's samples (x = 3 and 4) rise 20 units: blocked.
    EXPECT_EQ(cells[3], 0);
    EXPECT_EQ(cells[4], 0);
    EXPECT_EQ(cells[2], 1);
    std::vector<int> areas;
    EXPECT_EQ(faf::editor::ConnectAreas(cells, 8, 8, areas), 2);
    EXPECT_NE(areas[0], areas[7]);
    // A footprint without a slope limit walks over it.
    faf::editor::PathFootprint any = tank;
    any.maxSlope = 0.0f;
    const std::vector<std::uint8_t> all = faf::editor::PassableCells(heights.data(), 9, 9, false, 0.0f, any);
    EXPECT_EQ(faf::editor::ConnectAreas(all, 8, 8, areas), 1);
  }

  TEST(Pathing, WaterDepthDecidesForLandAndShips)
  {
    // Flat ground at 10 under a sea at 15: 5 units of water everywhere.
    const std::vector<std::uint16_t> heights(81, static_cast<std::uint16_t>(10 * 128));
    faf::editor::PathFootprint tank;
    tank.caps = 0x1;
    tank.maxSlope = 0.75f;
    tank.maxWaterDepth = 0.5f;
    EXPECT_EQ(faf::editor::PassableCells(heights.data(), 9, 9, true, 15.0f, tank)[0], 0);
    EXPECT_EQ(faf::editor::PassableCells(heights.data(), 9, 9, true, 10.2f, tank)[0], 1);
    faf::editor::PathFootprint ship;
    ship.caps = 0x8;
    ship.minWaterDepth = 1.5f;
    EXPECT_EQ(faf::editor::PassableCells(heights.data(), 9, 9, true, 15.0f, ship)[0], 1);
    EXPECT_EQ(faf::editor::PassableCells(heights.data(), 9, 9, true, 11.0f, ship)[0], 0);
    // Without a sea a ship goes nowhere.
    EXPECT_EQ(faf::editor::PassableCells(heights.data(), 9, 9, false, 15.0f, ship)[0], 0);
  }

  TEST(Pathing, AResourceBesideTheWayIsReached)
  {
    std::vector<int> areas(64, 0);
    areas[10] = 3; // cell (2, 1)
    EXPECT_EQ(faf::editor::AreaNear(areas, 8, 8, 3.5f, 1.5f, 2), 3);
    EXPECT_EQ(faf::editor::AreaNear(areas, 8, 8, 6.5f, 6.5f, 2), 0);
  }
} // namespace
