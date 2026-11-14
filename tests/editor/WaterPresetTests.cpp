// The map editor's water settings files (src/editor/doc/EdWaterPreset.cpp): FAForeverMapEditor's `.scmwtr`, read
// and written.

#include "editor/doc/EdWaterPreset.h"

#include <gtest/gtest.h>

namespace
{
  // As FAForeverMapEditor's ExportWater writes it (JsonUtility, pretty), cut to two wave layers' worth of detail.
  const char* const kFafme = R"({
    "HasWater": true,
    "Elevation": 17.5,
    "ElevationDeep": 15.0,
    "ElevationAbyss": 2.5,
    "SurfaceColor": {
        "x": 0.0,
        "y": 0.699999988079071,
        "z": 1.5
    },
    "ColorLerp": {
        "x": 0.06400000303983688,
        "y": 0.11900000274181366
    },
    "RefractionScale": 0.375,
    "FresnelBias": 0.15000000596046449,
    "FresnelPower": 1.5,
    "UnitReflection": 0.5,
    "SkyReflection": 1.5,
    "SunShininess": 50.0,
    "SunStrength": 10.0,
    "SunDirection": {
        "x": 0.09950000047683716,
        "y": -0.9604000449180603,
        "z": 0.2593000531196594
    },
    "SunColor": {
        "x": 0.5,
        "y": 0.4699999988079071,
        "z": 0.3499999940395355
    },
    "SunReflection": 5.0,
    "SunGlow": 0.10000000149011612,
    "TexPathCubemap": "/textures/environment/SkyCube_Evergreen01a.dds",
    "TexPathWaterRamp": "/textures/engine/waterramp.dds",
    "WaveTextures": [
        {
            "TexPath": "/textures/engine/waves.dds",
            "NormalMovement": {
                "x": 0.5,
                "y": -0.949999988079071
            },
            "NormalRepeat": 0.0008999999845400453
        },
        {
            "TexPath": "/textures/engine/waves.dds",
            "NormalMovement": {
                "x": 0.05000000074505806,
                "y": -0.0949999988079071
            },
            "NormalRepeat": 0.009999999776482582
        },
        {
            "TexPath": "/textures/engine/waves.dds",
            "NormalMovement": {
                "x": 0.009999999776482582,
                "y": 0.029999999329447746
            },
            "NormalRepeat": 0.05000000074505806
        },
        {
            "TexPath": "/textures/engine/waves.dds",
            "NormalMovement": {
                "x": 0.004999999888241291,
                "y": 0.014999999664723874
            },
            "NormalRepeat": 0.5
        }
    ]
})";

  TEST(
    WaterPreset,
    ReadsFafmesFile
  )
  {
    faf::editor::WaterState water;
    std::string error;
    ASSERT_TRUE(faf::editor::WaterFromScmwtr(kFafme, water, error)) << error;
    EXPECT_TRUE(water.enabled);
    EXPECT_FLOAT_EQ(water.elevation, 17.5f);
    EXPECT_FLOAT_EQ(water.shader.mWaterColor[1], 0.7f);
    EXPECT_FLOAT_EQ(water.shader.mWaterLerp[1], 0.119f);
    EXPECT_FLOAT_EQ(water.shader.mSunDirection[1], -0.9604f);
    EXPECT_FLOAT_EQ(water.shader.mSunReflectionAmount, 5.0f);
    EXPECT_FLOAT_EQ(water.shader.mNormalRepeatRate[3], 0.5f);
    EXPECT_FLOAT_EQ(water.shader.mNormal2Movement[1], -0.095f);
    EXPECT_EQ(water.textures[0], "/textures/environment/SkyCube_Evergreen01a.dds");
    EXPECT_EQ(water.textures[5], "/textures/engine/waves.dds");
  }

  TEST(
    WaterPreset,
    WritesWhatItReads
  )
  {
    faf::editor::WaterState water;
    std::string error;
    ASSERT_TRUE(faf::editor::WaterFromScmwtr(kFafme, water, error)) << error;
    faf::editor::WaterState again;
    ASSERT_TRUE(faf::editor::WaterFromScmwtr(faf::editor::WaterToScmwtr(water), again, error)) << error;
    EXPECT_TRUE(again == water);
    for (int i = 0; i < 6; ++i) {
      EXPECT_EQ(again.textures[i], water.textures[i]) << i;
    }
    EXPECT_FALSE(faf::editor::WaterFromScmwtr("{ \"Lighting\": 1 }", again, error));
  }

  TEST(
    WaterPreset,
    MotionPresetsChangeOnlyTheWaves
  )
  {
    faf::editor::WaterNumbers water;
    water.mFresnelPower = 7.0f;
    faf::editor::ApplyWaterMotionPreset(water, 0);
    EXPECT_FLOAT_EQ(water.mNormal1Movement[0], 0.5f);
    EXPECT_FLOAT_EQ(water.mNormal1Movement[1], -0.95f);
    EXPECT_FLOAT_EQ(water.mNormalRepeatRate[3], 0.5f);
    faf::editor::ApplyWaterMotionPreset(water, 1);
    EXPECT_FLOAT_EQ(water.mNormal1Movement[0], 0.125f) << "calm: a quarter";
    faf::editor::ApplyWaterMotionPreset(water, 2);
    EXPECT_FLOAT_EQ(water.mNormal2Movement[1], -0.2375f);
    EXPECT_FLOAT_EQ(water.mNormalRepeatRate[0], 0.00135f);
    EXPECT_FLOAT_EQ(water.mFresnelPower, 7.0f) << "the rest kept";
    EXPECT_STREQ(faf::editor::WaterMotionPresetName(3), "Ocean swell");
  }
} // namespace
