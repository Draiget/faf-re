// The Lighting panel's conversions (src/editor/ui/EdColourText.h, src/editor/doc/EdLighting.h): a colour's hex and
// brightness (colours brighter than white keep their scale through a hex edit) and the sun's direction as an azimuth
// and an elevation.

#include "editor/doc/EdLighting.h"
#include "editor/ui/EdColourText.h"

#include <gtest/gtest.h>

namespace
{
  using faf::editor::ColourBrightness;
  using faf::editor::ColourOfHex;
  using faf::editor::HexOfColour;

  TEST(
    ColourText,
    HexRoundTripsAndKeepsTheBrightness
  )
  {
    float sun[3] = {1.0f, 0.902f, 0.761f};
    EXPECT_EQ(HexOfColour(sun), "#FFE6C2");
    float bright[3] = {1.38f, 1.29f, 1.14f}; // SCMP_009's sun colour
    EXPECT_FLOAT_EQ(ColourBrightness(bright), 1.38f);
    EXPECT_EQ(HexOfColour(bright), "#FFEED3");
    float back[3] = {};
    ASSERT_TRUE(ColourOfHex(HexOfColour(bright), ColourBrightness(bright), back));
    for (int i = 0; i < 3; ++i) {
      EXPECT_NEAR(back[i], bright[i], 0.01f) << "component " << i;
    }
    float typed[3] = {0.2f, 0.2f, 0.2f};
    EXPECT_TRUE(ColourOfHex("58606b", 1.0f, typed));
    EXPECT_NEAR(typed[0], 0x58 / 255.0f, 1e-6f);
    EXPECT_TRUE(ColourOfHex(" #fff ", 1.0f, typed));
    EXPECT_FLOAT_EQ(typed[2], 1.0f);
    float kept[3] = {0.1f, 0.2f, 0.3f};
    EXPECT_FALSE(ColourOfHex("#12345", 1.0f, kept));
    EXPECT_FALSE(ColourOfHex("#GG0000", 1.0f, kept));
    EXPECT_FLOAT_EQ(kept[1], 0.2f) << "a bad hex leaves the colour";
  }

  TEST(
    ColourText,
    TheSunsDirectionReadsAsAzimuthAndElevation
  )
  {
    // SCMP_009's sun direction.
    const float direction[3] = {0.616f, 0.559f, 0.555f};
    float azimuth = 0.0f;
    float elevation = 0.0f;
    faf::editor::SunAnglesOf(direction, azimuth, elevation);
    EXPECT_NEAR(azimuth, 42.0f, 0.5f);
    EXPECT_NEAR(elevation, 34.0f, 0.5f);
    float back[3] = {};
    faf::editor::SunDirectionOf(azimuth, elevation, back);
    for (int i = 0; i < 3; ++i) {
      EXPECT_NEAR(back[i], direction[i], 0.002f) << "component " << i;
    }
    const float up[3] = {0.0f, 0.0f, 0.0f};
    faf::editor::SunAnglesOf(up, azimuth, elevation);
    EXPECT_FLOAT_EQ(elevation, 90.0f) << "a zero vector: straight up";
  }
} // namespace
