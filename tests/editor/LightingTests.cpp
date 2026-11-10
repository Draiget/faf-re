// The map editor's lighting settings files (src/editor/doc/EdLighting.cpp): FAForeverMapEditor's `.scmlighting`, read
// and written.

#include "editor/doc/EdLighting.h"

#include <gtest/gtest.h>
#include <iterator>
#include <fstream>
#include <filesystem>
#include <cstdlib>
#include <cmath>

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
  TEST(Lighting, ReadsEveryRetailMapsLighting)
  {
    const char* const folder = std::getenv("FAF_RETAIL_MAPS");
    if (folder == nullptr) {
      GTEST_SKIP() << "FAF_RETAIL_MAPS is not set";
    }
    int maps = 0;
    for (const auto& map : std::filesystem::directory_iterator(folder)) {
      const std::filesystem::path file = map.path() / (map.path().filename().string() + ".scmap");
      std::ifstream in(file, std::ios::binary);
      if (!in) {
        continue;
      }
      const std::string bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
      faf::editor::LightingState lighting;
      std::string error;
      ASSERT_TRUE(faf::editor::LightingFromScmap(bytes, lighting, error)) << file << ": " << error;
      // A unit sun direction and a multiplier in the game's range: the read landed on the block.
      const float length = std::sqrt(lighting.sunDirection[0] * lighting.sunDirection[0] + lighting.sunDirection[1] * lighting.sunDirection[1] +
                                     lighting.sunDirection[2] * lighting.sunDirection[2]);
      EXPECT_NEAR(length, 1.0f, 0.02f) << file;
      EXPECT_GT(lighting.multiplier, 0.0f) << file;
      EXPECT_LT(lighting.multiplier, 10.0f) << file;
      if (map.path().filename() == "SCMP_009") {
        // What the editor's own export of SCMP_009's lighting gave (the terrain's values).
        EXPECT_NEAR(lighting.multiplier, 1.54f, 1e-5f);
        EXPECT_NEAR(lighting.sunDirection[0], 0.616095066f, 1e-6f);
        EXPECT_NEAR(lighting.fogEnd, 740.0f, 1e-3f);
        EXPECT_NEAR(lighting.bloom, 0.036249999f, 1e-7f);
      }
      ++maps;
    }
    EXPECT_GT(maps, 0);
    std::printf("[ lighting ] %d retail maps' lighting read\n", maps);
  }
} // namespace
