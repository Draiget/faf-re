// The map editor's sky files (src/editor/doc/EdSkybox.cpp): FAForeverMapEditor's `.scmskybox`, read and written.

#include "editor/doc/EdSkybox.h"

#include <gtest/gtest.h>

namespace
{
  using faf::editor::SkyboxState;

  // As FAFME's ExportProceduralSkybox writes it (JsonUtility, pretty): one planet, two cirrus layers.
  const char* const kFafme = R"({
    "Data": {
        "Position": {
            "x": 512.0,
            "y": 0.0,
            "z": 512.0
        },
        "Scale": 4686.0,
        "SubtractHeight": 1.2566369771957398,
        "SubdivisionsAxis": 16,
        "SubdivisionsHeight": 6,
        "HorizonHeight": -35.45000076293945,
        "ZenithHeight": 349.0,
        "HorizonColor": {
            "r": 0.5,
            "g": 0.6000000238418579,
            "b": 0.800000011920929,
            "a": 1.0
        },
        "ZenithColor": {
            "r": 0.10000000149011612,
            "g": 0.20000000298023225,
            "b": 0.699999988079071,
            "a": 1.0
        },
        "DecalGlowMultiplier": 0.10000000149011612,
        "Albedo": "/textures/environment/Decal_test_Albedo003.dds",
        "Glow": "/textures/environment/Decal_test_Glow003.dds",
        "Planets": [
            {
                "Position": {
                    "x": 100.0,
                    "y": 2000.0,
                    "z": -300.0
                },
                "Rotation": 0.5,
                "Scale": {
                    "x": 250.0,
                    "y": 250.0
                },
                "Uv": {
                    "x": 0.0,
                    "y": 0.5,
                    "z": 0.5,
                    "w": 1.0
                }
            }
        ],
        "MidRgbColor": {
            "r": 0,
            "g": 0,
            "b": 0,
            "a": 0
        },
        "CirrusMultiplier": 1.7999999523162842,
        "CirrusColor": {
            "r": 1.0,
            "g": 0.8999999761581421,
            "b": 0.800000011920929,
            "a": 1.0
        },
        "CirrusTexture": "/textures/environment/cirrus000.dds",
        "CirrusLayers": [
            {
                "frequency": {
                    "x": 0.0010000000474974514,
                    "y": 0.0010000000474974514
                },
                "Speed": 0.009999999776482582,
                "Direction": {
                    "x": 1.0,
                    "y": 0.0
                }
            },
            {
                "frequency": {
                    "x": 0.0020000000949949028,
                    "y": 0.0020000000949949028
                },
                "Speed": 0.019999999552965165,
                "Direction": {
                    "x": 0.0,
                    "y": 1.0
                }
            }
        ],
        "Clouds7": 0.0
    }
})";

  TEST(
    Skybox,
    ReadsFafmesFile
  )
  {
    SkyboxState sky;
    std::string error;
    ASSERT_TRUE(faf::editor::SkyboxFromScmskybox(kFafme, sky, error)) << error;
    // The sky's own Position and Scale, not the planet's.
    EXPECT_FLOAT_EQ(sky.position[0], 512.0f);
    EXPECT_FLOAT_EQ(sky.scale, 4686.0f);
    EXPECT_FLOAT_EQ(sky.horizonHeight, -35.45f);
    EXPECT_EQ(sky.subdivisionsAxis, 16);
    EXPECT_FLOAT_EQ(sky.horizonColor[1], 0.6f);
    EXPECT_FLOAT_EQ(sky.zenithColor[2], 0.7f);
    EXPECT_EQ(sky.albedo, "/textures/environment/Decal_test_Albedo003.dds");
    ASSERT_EQ(sky.planets.size(), 1u);
    EXPECT_FLOAT_EQ(sky.planets[0].position[1], 2000.0f);
    EXPECT_FLOAT_EQ(sky.planets[0].scale[0], 250.0f);
    EXPECT_FLOAT_EQ(sky.planets[0].uv[1], 0.5f);
    EXPECT_FLOAT_EQ(sky.cirrusColor[1], 0.9f);
    EXPECT_FLOAT_EQ(sky.cirrus[1].speed, 0.02f);
    EXPECT_FLOAT_EQ(sky.cirrus[1].direction[1], 1.0f);
    // The game has four layers: the missing two stay zero.
    EXPECT_FLOAT_EQ(sky.cirrus[3].speed, 0.0f);
  }

  TEST(
    Skybox,
    WritesWhatItReads
  )
  {
    SkyboxState sky;
    std::string error;
    ASSERT_TRUE(faf::editor::SkyboxFromScmskybox(kFafme, sky, error)) << error;
    sky.planets.push_back({});
    SkyboxState again;
    ASSERT_TRUE(faf::editor::SkyboxFromScmskybox(faf::editor::SkyboxToScmskybox(sky), again, error)) << error;
    EXPECT_TRUE(again == sky);
    // No planets is a sky too.
    sky.planets.clear();
    ASSERT_TRUE(faf::editor::SkyboxFromScmskybox(faf::editor::SkyboxToScmskybox(sky), again, error)) << error;
    EXPECT_TRUE(again == sky);
    EXPECT_FALSE(faf::editor::SkyboxFromScmskybox("{ \"LightingMultiplier\": 1 }", again, error));
  }
} // namespace
