// The map editor's lighting settings files (src/editor/doc/EdLighting.cpp): FAForeverMapEditor's `.scmlighting`, read
// and written.

#include "editor/doc/EdLighting.h"

#include <gtest/gtest.h>

namespace
{
  // As FAForeverMapEditor's ExportLightingData writes it (JsonUtility, pretty).
  const char* const kFafme = R"({
    "LightingMultiplier": 1.5,
    "SunDirection": {
        "x": 0.7071068286895752,
        "y": 0.7071068286895752,
        "z": 0.0
    },
    "SunAmbience": {
        "x": 0.20000000298023225,
        "y": 0.20000000298023225,
        "z": 0.20000000298023225
    },
    "SunColor": {
        "x": 1.2000000476837159,
        "y": 1.100000023841858,
        "z": 1.0
    },
    "ShadowFillColor": {
        "x": 0.30000001192092898,
        "y": 0.30000001192092898,
        "z": 0.4000000059604645
    },
    "SpecularColor": {
        "x": 0.0,
        "y": 0.0,
        "z": 0.0,
        "w": 0.0
    },
    "Bloom": 0.07999999821186066,
    "FogColor": {
        "x": 0.5,
        "y": 0.6000000238418579,
        "z": 0.699999988079071
    },
    "FogStart": 50.0,
    "FogEnd": 1500.0
})";

  TEST(Lighting, ReadsFafmesFile)
  {
    faf::editor::LightingState lighting;
    std::string error;
    ASSERT_TRUE(faf::editor::LightingFromScmlighting(kFafme, lighting, error)) << error;
    EXPECT_FLOAT_EQ(lighting.multiplier, 1.5f);
    EXPECT_FLOAT_EQ(lighting.sunDirection[0], 0.70710683f);
    EXPECT_FLOAT_EQ(lighting.sunColor[0], 1.2f);
    EXPECT_FLOAT_EQ(lighting.shadowFill[2], 0.4f);
    EXPECT_FLOAT_EQ(lighting.bloom, 0.08f);
    EXPECT_FLOAT_EQ(lighting.fogColor[1], 0.6f);
    EXPECT_FLOAT_EQ(lighting.fogStart, 50.0f);
    EXPECT_FLOAT_EQ(lighting.fogEnd, 1500.0f);
  }

  TEST(Lighting, WritesWhatItReads)
  {
    faf::editor::LightingState lighting;
    std::string error;
    ASSERT_TRUE(faf::editor::LightingFromScmlighting(kFafme, lighting, error)) << error;
    faf::editor::LightingState again;
    ASSERT_TRUE(faf::editor::LightingFromScmlighting(faf::editor::LightingToScmlighting(lighting), again, error)) << error;
    EXPECT_TRUE(again == lighting);
    EXPECT_FALSE(faf::editor::LightingFromScmlighting("{ \"SurfaceColor\": 1 }", again, error));
  }
} // namespace
