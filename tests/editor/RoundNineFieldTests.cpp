// The seventh comparison with FAF Studio (field target): the unit icon's light edge and the difference picture.

#include "editor/tools/EdUnitIcon.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

namespace
{
  using namespace faf::editor;

  TEST(
    RoundNineField,
    TheLightEdgeIsAWhiteHaloRoundTheUnit
  )
  {
    // A 16 x 16 icon with a dark 4 x 4 square in the middle.
    constexpr int kSide = 16;
    std::vector<float> rgba(kSide * kSide * 4, 0.0f);
    for (int y = 6; y < 10; ++y) {
      for (int x = 6; x < 10; ++x) {
        float* p = &rgba[(y * kSide + x) * 4];
        p[0] = p[1] = p[2] = 0.2f;
        p[3] = 1.0f;
      }
    }
    std::vector<float> plain = rgba;
    IconLightEdge(plain, kSide, 0.0f, 0.0f);
    EXPECT_EQ(plain, rgba) << "off: nothing changes";
    IconLightEdge(rgba, kSide, 2.0f, 2.0f, 0.65f);
    const auto at = [&](const int x, const int y) {
      return &rgba[(y * kSide + x) * 4];
    };
    EXPECT_FLOAT_EQ(at(7, 7)[0], 0.2f) << "the unit stays as it was";
    EXPECT_FLOAT_EQ(at(7, 7)[3], 1.0f);
    EXPECT_NEAR(at(5, 7)[3], 0.65f, 1e-4f) << "one pixel out: the solid halo";
    EXPECT_FLOAT_EQ(at(5, 7)[0], 1.0f) << "white";
    EXPECT_GT(at(3, 7)[3], 0.0f) << "three out: fading";
    EXPECT_LT(at(3, 7)[3], 0.65f);
    EXPECT_FLOAT_EQ(at(0, 0)[3], 0.0f) << "far: clear";
    EXPECT_FLOAT_EQ(at(0, 0)[0], 1.0f) << "clear white, as the game's files";
  }

  TEST(
    RoundNineField,
    TheDifferencePictureColoursEachSilhouette
  )
  {
    // Made: alpha in pixels 0 and 1; the game's: in 1 and 2; neither in 3.
    const std::uint8_t made[16] = {0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0};
    const std::uint8_t shipped[16] = {0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 0};
    const std::vector<std::uint32_t> diff = IconDifference(made, shipped, 2);
    ASSERT_EQ(diff.size(), 4U);
    EXPECT_EQ(diff[0], 0xFFDC463Cu) << "only the render: red";
    EXPECT_EQ(diff[1], 0xFF3CBE5Au) << "both: green";
    EXPECT_EQ(diff[2], 0xFF466EE6u) << "only the game's: blue";
    EXPECT_EQ(diff[3], 0xFF282828u) << "neither: dark grey";
  }
} // namespace
