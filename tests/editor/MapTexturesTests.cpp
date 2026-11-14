// Map-wide textures (src/editor/tools/EdMapTextures.cpp, FAF Studio's maptextures.lua): where each kind goes for a
// shader, the water depth, and the packed channels made from heights through the field library's ops.

#include "editor/tools/EdMapTextures.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <vector>

namespace
{
  using faf::editor::GroundKind;
  using faf::editor::MakeMapTexture;
  using faf::editor::MakePaintTexture;
  using faf::editor::MapPaint;
  using faf::editor::MapPaintOptions;
  using faf::editor::MapTextureKind;
  using faf::editor::MapTextureOptions;
  using faf::editor::VisibleWeights;
  using faf::editor::MapTexturePack;
  using faf::editor::MapTextureTargetOf;
  using faf::editor::WaterDepthAt;

  float Channel(
    const std::vector<float>& rgba,
    const int size,
    const int x,
    const int y,
    const int c
  )
  {
    return rgba
      [(static_cast<std::size_t>(y) * static_cast<std::size_t>(size) + static_cast<std::size_t>(x)) * 4U +
       static_cast<std::size_t>(c)];
  }

  TEST(
    MapTextures,
    EachShaderHasItsSlot
  )
  {
    const auto pbr = MapTextureTargetOf("TerrainPBR", MapTextureKind::Normals);
    EXPECT_EQ(pbr.slot, 9);
    EXPECT_EQ(pbr.pack, MapTexturePack::Light301);
    EXPECT_EQ(MapTextureTargetOf("Terrain301", MapTextureKind::Lighting).pack, MapTexturePack::Light301)
      << "one texture for both kinds";
    const auto normals = MapTextureTargetOf("Terrain250", MapTextureKind::Normals);
    EXPECT_EQ(normals.slot, 8);
    EXPECT_TRUE(normals.normalsPath);
    EXPECT_EQ(normals.pack, MapTexturePack::Normal7);
    const auto lighting = MapTextureTargetOf("Terrain250", MapTextureKind::Lighting);
    EXPECT_EQ(lighting.slot, 8);
    EXPECT_FALSE(lighting.normalsPath);
    EXPECT_EQ(lighting.pack, MapTexturePack::Info7);
    EXPECT_FALSE(MapTextureTargetOf("TTerrain", MapTextureKind::Normals).Valid()) << "GPG's shaders have none";
    const auto specular = MapTextureTargetOf("Terrain001", MapTextureKind::Specular);
    EXPECT_EQ(specular.slot, 9);
    EXPECT_EQ(specular.pack, MapTexturePack::Specular);
    EXPECT_FALSE(MapTextureTargetOf("Terrain000", MapTextureKind::Specular).Valid()) << "its Upper is a macrotexture";
    EXPECT_EQ(MapTextureTargetOf("TTerrainXP", MapTextureKind::Macro).pack, MapTexturePack::Macro);
    EXPECT_EQ(MapTextureTargetOf("Terrain050", MapTextureKind::Macro).slot, 9);
    EXPECT_FALSE(MapTextureTargetOf("Terrain001", MapTextureKind::Macro).Valid()) << "its Upper is the specular";
    EXPECT_FALSE(MapTextureTargetOf("Terrain250", MapTextureKind::Macro).Valid()) << "its Upper is an atlas";
  }

  /** One mask texel with layer `layer`'s byte set to `value`. */
  std::uint64_t Texel(
    const int layer,
    const std::uint8_t value
  )
  {
    return static_cast<std::uint64_t>(value) << (8 * (layer - 1));
  }

  TEST(
    MapTextures,
    TheTopLayerHidesWhatIsUnderIt
  )
  {
    MapPaint paint;
    paint.layers[1].textured = true;
    paint.layers[2].textured = true;
    paint.layers[3].textured = false; // painted, but no texture: shows nothing
    // Texel 0: layer 1 full and layer 2 half. Texel 1: nothing painted. Texel 2: layer 3 only.
    const std::uint64_t texels[3] = {Texel(1, 255) | Texel(2, 128), 0, Texel(3, 255)};
    VisibleWeights(texels, 3, 1, 7, 0, paint);
    EXPECT_NEAR(paint.layers[2].visible[0], 128.0f / 255.0f, 1e-5f);
    EXPECT_NEAR(paint.layers[1].visible[0], 127.0f / 255.0f, 1e-5f) << "what layer 2 leaves free";
    EXPECT_NEAR(paint.layers[0].visible[0], 0.0f, 1e-5f);
    EXPECT_NEAR(paint.layers[0].visible[1], 1.0f, 1e-5f) << "the base layer shows where nothing is painted";
    EXPECT_NEAR(paint.layers[3].visible[2], 0.0f, 1e-5f);
    EXPECT_NEAR(paint.layers[0].visible[2], 1.0f, 1e-5f) << "an untextured layer's paint shows the base";
    // Half range: a byte of 128 shows (2 * 128 - 255) / 255.
    VisibleWeights(texels, 3, 1, 7, 0xFF, paint);
    EXPECT_NEAR(paint.layers[2].visible[0], 1.0f / 255.0f, 1e-5f);
  }

  TEST(
    MapTextures,
    TheMacroHasThePaintsColourAndTheSpecularShinesOnWetGround
  )
  {
    constexpr int kSide = 33;
    const std::vector<float> heights(static_cast<std::size_t>(kSide) * kSide, 40.0f);
    MapPaint paint;
    paint.layers[0].textured = true;
    paint.layers[0].colour = {0.2f, 0.4f, 0.6f};
    paint.layers[0].kind = GroundKind::Grass;
    paint.layers[1].textured = true;
    paint.layers[1].colour = {0.8f, 0.8f, 0.8f};
    paint.layers[1].kind = GroundKind::Wet;
    // Layer 1 painted on the left half of a 4 x 4 mask grid.
    std::vector<std::uint64_t> texels(16, 0);
    for (int z = 0; z < 4; ++z) {
      texels[static_cast<std::size_t>(z) * 4] = Texel(1, 255);
      texels[static_cast<std::size_t>(z) * 4 + 1] = Texel(1, 255);
    }
    VisibleWeights(texels.data(), 4, 4, 7, 0, paint);
    MapTextureOptions options;
    options.waterOn = false;
    MapPaintOptions paintOptions;
    paintOptions.contrast = 0.0f; // no patches: the plain colour
    std::vector<float> rgba;
    std::string error;
    ASSERT_TRUE(MakePaintTexture(
      heights,
      kSide,
      kSide,
      paint,
      MapTextureTargetOf("TTerrainXP", MapTextureKind::Macro),
      options,
      paintOptions,
      32,
      rgba,
      error
    )) << error;
    EXPECT_NEAR(Channel(rgba, 32, 4, 16, 0), 0.8f, 1e-3f) << "layer 1's colour on the left";
    EXPECT_NEAR(Channel(rgba, 32, 28, 16, 2), 0.6f, 1e-3f) << "the base's blue on the right";
    EXPECT_NEAR(Channel(rgba, 32, 28, 16, 3), paintOptions.opacity, 1e-6f);
    ASSERT_TRUE(MakePaintTexture(
      heights,
      kSide,
      kSide,
      paint,
      MapTextureTargetOf("Terrain001", MapTextureKind::Specular),
      options,
      paintOptions,
      32,
      rgba,
      error
    )) << error;
    EXPECT_NEAR(Channel(rgba, 32, 4, 16, 0), 0.08f + paintOptions.strength, 1e-3f) << "wet ground shines";
    EXPECT_NEAR(Channel(rgba, 32, 28, 16, 0), 0.08f, 1e-3f) << "grass hardly";
    EXPECT_NEAR(Channel(rgba, 32, 4, 16, 3), 0.75f, 1e-3f) << "sharper where it shines";
    // The waterline shines too.
    options.waterOn = true;
    options.waterElevation = 41.0f;
    ASSERT_TRUE(MakePaintTexture(
      heights,
      kSide,
      kSide,
      paint,
      MapTextureTargetOf("Terrain001", MapTextureKind::Specular),
      options,
      paintOptions,
      32,
      rgba,
      error
    )) << error;
    EXPECT_NEAR(Channel(rgba, 32, 28, 16, 0), 0.08f + 0.9f * paintOptions.strength, 1e-3f);
  }

  TEST(
    MapTextures,
    WaterDepthFromTheSeaToTheAbyss
  )
  {
    MapTextureOptions options;
    options.waterElevation = 20.0f;
    options.abyss = 0.0f;
    EXPECT_FLOAT_EQ(WaterDepthAt(30.0f, options), 0.0f) << "land";
    EXPECT_FLOAT_EQ(WaterDepthAt(10.0f, options), 0.5f);
    EXPECT_FLOAT_EQ(WaterDepthAt(0.0f, options), 1.0f);
    EXPECT_FLOAT_EQ(WaterDepthAt(-5.0f, options), 1.0f) << "below the abyss stays 1";
    options.waterOn = false;
    EXPECT_FLOAT_EQ(WaterDepthAt(0.0f, options), 0.0f) << "no sea";
  }

  TEST(
    MapTextures,
    AFlatMapIsUpOpenAndLit
  )
  {
    constexpr int kSide = 33;
    const std::vector<float> heights(static_cast<std::size_t>(kSide) * kSide, 40.0f);
    MapTextureOptions options;
    options.waterElevation = 20.0f;
    std::vector<float> rgba;
    std::string error;
    ASSERT_TRUE(MakeMapTexture(
      heights, kSide, kSide, MapTextureTargetOf("Terrain250", MapTextureKind::Normals), options, 32, rgba, error
    )) << error;
    EXPECT_NEAR(Channel(rgba, 32, 16, 16, 0), 0.5f, 1e-3f) << "the normal's z: flat";
    EXPECT_NEAR(Channel(rgba, 32, 16, 16, 3), 0.5f, 1e-3f) << "the normal's x: flat";
    ASSERT_TRUE(MakeMapTexture(
      heights, kSide, kSide, MapTextureTargetOf("Terrain250", MapTextureKind::Lighting), options, 32, rgba, error
    )) << error;
    EXPECT_FLOAT_EQ(Channel(rgba, 32, 16, 16, 0), 0.0f) << "no water over land";
    EXPECT_NEAR(Channel(rgba, 32, 16, 16, 1), 1.0f, 1e-3f) << "open sky";
    EXPECT_NEAR(Channel(rgba, 32, 16, 16, 3), 1.0f, 1e-3f) << "in the sun";
  }

  TEST(
    MapTextures,
    APillarShadesTheGroundAwayFromTheSun
  )
  {
    constexpr int kSide = 65;
    std::vector<float> heights(static_cast<std::size_t>(kSide) * kSide, 10.0f);
    // A pillar 30 units tall in the middle.
    for (int z = 30; z <= 34; ++z) {
      for (int x = 30; x <= 34; ++x) {
        heights[static_cast<std::size_t>(z) * kSide + static_cast<std::size_t>(x)] = 40.0f;
      }
    }
    MapTextureOptions options;
    options.azimuth = 0.0f; // the sun towards +x
    options.altitude = 30.0f;
    options.soft = 0.0f;
    options.quality = 1;
    options.occlusion = 0.0f;
    options.waterOn = false;
    std::vector<float> rgba;
    std::string error;
    ASSERT_TRUE(MakeMapTexture(
      heights, kSide, kSide, MapTextureTargetOf("Terrain250", MapTextureKind::Lighting), options, 64, rgba, error
    )) << error;
    // Away from the sun (-x of the pillar) lies its shadow; towards it, sun.
    EXPECT_LT(Channel(rgba, 64, 22, 32, 3), 0.5f) << "in the pillar's shadow";
    EXPECT_GT(Channel(rgba, 64, 42, 32, 3), 0.5f) << "on the sun's side";
  }
} // namespace
