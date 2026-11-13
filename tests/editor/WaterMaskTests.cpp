// The water's masks (src/editor/tools/EdWaterMasks.cpp): a dab towards a value with falloff, its changed cells, and the
// overlay's bands.

#include "editor/tools/EdWaterMasks.h"

#include <gtest/gtest.h>

#include <vector>

namespace
{
  using faf::editor::PaintWaterMask;
  using faf::editor::WaterMask;
  using faf::editor::WaterMaskBands;
  using faf::editor::WaterMaskBrush;
  using faf::editor::WaterMaskDefault;

  constexpr int kSide = 32; // a 64-unit map

  TEST(
    WaterMasks,
    ADabMovesCellsTowardsTheValueInsideTheRadius
  )
  {
    std::vector<std::uint8_t> cells(kSide * kSide, 0);
    WaterMaskBrush brush;
    brush.radius = 10.0f;
    brush.strength = 1.0f;
    brush.falloff = 0.0f;
    brush.value = 200;
    const auto rect = PaintWaterMask(cells.data(), kSide, kSide, 31.0f, 31.0f, brush);
    ASSERT_FALSE(rect.Empty());
    EXPECT_EQ(cells[15 * kSide + 15], 200) << "the cell under the middle (its middle at 31, 31)";
    EXPECT_EQ(cells[15 * kSide + 19], 200) << "8 units off, inside the hard radius";
    EXPECT_EQ(cells[15 * kSide + 21], 0) << "12 units off, outside";
    EXPECT_EQ(cells[0], 0);
    EXPECT_LE(rect.x0, 11);
    EXPECT_GE(rect.x1, 20);
    for (int j = 0; j < kSide; ++j) {
      for (int i = 0; i < kSide; ++i) {
        if (cells[static_cast<std::size_t>(j * kSide + i)] != 0) {
          EXPECT_TRUE(i >= rect.x0 && i < rect.x1 && j >= rect.z0 && j < rect.z1) << "changed cells are in the rect";
        }
      }
    }
  }

  TEST(
    WaterMasks,
    FalloffAndStrengthSoftenButStillFinish
  )
  {
    std::vector<std::uint8_t> cells(kSide * kSide, 0);
    WaterMaskBrush brush;
    brush.radius = 12.0f;
    brush.strength = 0.25f;
    brush.falloff = 1.0f;
    brush.value = 255;
    (void)PaintWaterMask(cells.data(), kSide, kSide, 31.0f, 31.0f, brush);
    const int middle = cells[15 * kSide + 15];
    const int edge = cells[15 * kSide + 20]; // 10 units off
    EXPECT_GT(middle, edge) << "softer towards the edge";
    EXPECT_LT(middle, 255) << "a quarter strength doesn't get there at once";
    for (int dab = 0; dab < 400; ++dab) {
      (void)PaintWaterMask(cells.data(), kSide, kSide, 31.0f, 31.0f, brush);
    }
    EXPECT_EQ(cells[15 * kSide + 15], 255) << "weak dabs still finish (a step at least)";
    EXPECT_EQ(cells[15 * kSide + 20], 255);
    // Nothing left to do: an empty rect.
    std::vector<std::uint8_t> full(kSide * kSide, 255);
    EXPECT_TRUE(PaintWaterMask(full.data(), kSide, kSide, 31.0f, 31.0f, brush).Empty());
    // Off the map: nothing, no crash.
    EXPECT_TRUE(PaintWaterMask(cells.data(), kSide, kSide, -100.0f, -100.0f, brush).Empty());
  }

  TEST(
    WaterMasks,
    BandsSkipTheDefault
  )
  {
    std::vector<std::uint8_t> cells = {255, 0, 128, 255};
    const auto flat = WaterMaskBands(cells.data(), 2, 2, WaterMask::Flatness);
    EXPECT_EQ(flat[0], 0) << "flatness 255 is the default";
    EXPECT_EQ(flat[1], 1);
    EXPECT_EQ(flat[2], 5);
    const auto foam = WaterMaskBands(cells.data(), 2, 2, WaterMask::Foam);
    EXPECT_EQ(foam[1], 0) << "foam 0 is the default";
    EXPECT_EQ(foam[0], 8);
    EXPECT_EQ(WaterMaskDefault(WaterMask::DepthBias), 0x7F);
  }
} // namespace
