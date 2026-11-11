// The map editor's view aids (src/editor/tools/EdViewAids.cpp): the game's cell slope in bands, the ruler's text.

#include "editor/tools/EdViewAids.h"

#include <gtest/gtest.h>

namespace
{
  TEST(
    ViewAids,
    SlopeIsTheSteepestEdgeInBands
  )
  {
    // 3 x 3 samples (2 x 2 cells), heights in words (128 a unit, the game's scale).
    const std::uint16_t heights[9] = {
      0,
      32,
      64, //
      0,
      32,
      64, //
      0,
      96,
      200, //
    };
    const float scale = 1.0f / 128.0f;
    // Near cells: every edge rises 32 or 0 words: 0.25, not above the first band.
    EXPECT_FLOAT_EQ(faf::editor::CellSlope(heights, 3, 0, 0, scale), 0.25f);
    // Far left: edges 96 (0 to 96), 64 (32 to 96), 0, 32: 0.75.
    EXPECT_FLOAT_EQ(faf::editor::CellSlope(heights, 3, 0, 1, scale), 0.75f);
    // Far right: edges 104 (96 to 200), 136 (64 to 200), 64, 32: the steepest, 136 words.
    EXPECT_FLOAT_EQ(faf::editor::CellSlope(heights, 3, 1, 1, scale), 136.0f / 128.0f);
    const std::vector<std::uint8_t> bands = faf::editor::SlopeBands(heights, 3, 3, scale);
    ASSERT_EQ(bands.size(), 4u);
    EXPECT_EQ(bands[0], 0);
    EXPECT_EQ(bands[1], 0);
    EXPECT_EQ(bands[2], 2);
    EXPECT_EQ(bands[3], 3);
  }

  TEST(
    ViewAids,
    DistanceInUnitsAndKilometres
  )
  {
    EXPECT_EQ(faf::editor::DistanceText(1024.0f), "1024.0 units, 20.00 km");
    EXPECT_EQ(faf::editor::DistanceText(25.6f), "25.6 units, 0.50 km");
  }
} // namespace
