// Looks (src/editor/doc/EdLooks.cpp): a map's lighting, water and sky read from its .scmap, and looks blended by
// section.

#include "editor/doc/EdLooks.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>

namespace
{
  using faf::editor::BlendLook;
  using faf::editor::kLookAll;
  using faf::editor::kLookLighting;
  using faf::editor::kLookSky;
  using faf::editor::kLookWater;
  using faf::editor::kLookWaves;
  using faf::editor::Look;
  using faf::editor::LookFromScmap;

  /** A small .scmap, block by block in CWldTerrainRes::Load's order. */
  class MapWriter
  {
  public:
    template <class T>
    void Put(
      const T& value
    )
    {
      mBytes.append(reinterpret_cast<const char*>(&value), sizeof(T));
    }
    void Str(
      const std::string& text
    )
    {
      mBytes += text;
      mBytes.push_back('\0');
    }
    void Zeros(
      const std::size_t count
    )
    {
      mBytes.append(count, '\0');
    }
    void Floats(
      const int count,
      const float first
    )
    {
      for (int i = 0; i < count; ++i) {
        Put(first + static_cast<float>(i));
      }
    }
    std::string mBytes;
  };

  std::string SmallMap(
    const bool withSky
  )
  {
    constexpr std::int32_t kSide = 8;
    MapWriter m;
    m.mBytes = "Map\x1a";
    m.Zeros(4 + 4 + 4 + 4 + 4 + 4 + 2);
    m.Put(std::int32_t{3}); // preview bytes
    m.Zeros(3);
    m.Put(std::int32_t{60}); // version
    m.Put(kSide);
    m.Put(kSide);
    m.Put(0.0078125f);
    m.Zeros((kSide + 1) * (kSide + 1) * 2);
    m.Put(std::uint8_t{0}); // shader byte
    m.Str("TTerrain");
    m.Str("/textures/environment/defaultbackground.dds");
    m.Str("/textures/environment/defaultskycube.dds");
    m.Put(std::int32_t{1});
    m.Str("<default>");
    m.Str("/textures/environment/defaultenvcube.dds");
    m.Floats(23, 1.0f); // lighting: 1, 2, 3, ...
    m.Put(std::uint8_t{1});
    m.Put(17.5f);
    m.Put(15.0f);
    m.Put(2.5f);
    m.Floats(20, 100.0f); // the water shader's header: 100, 101, ...
    m.Str("/textures/engine/waterCubemap.dds");
    m.Str("/textures/engine/waterramp.dds");
    m.Floats(4, 200.0f); // normal repeat
    for (int wave = 0; wave < 4; ++wave) {
      m.Put(0.5f + static_cast<float>(wave));
      m.Put(-0.25f);
      m.Str("/textures/engine/waves" + std::to_string(wave) + ".dds");
    }
    m.Put(std::int32_t{1}); // one wave generator
    m.Str("/env/common/props/shore_a.dds");
    m.Str("/env/common/props/shore_ramp.dds");
    m.Zeros(13 * 4 + 4 * 4);
    m.Zeros(24 + 4); // palette, imager offset
    for (int layer = 0; layer < 19; ++layer) {
      m.Str(layer == 0 ? "/env/evergreen/layers/eg_gravel005_albedo.dds" : "");
      m.Put(4.0f);
    }
    m.Zeros(8);
    m.Put(std::uint32_t{1}); // one decal
    m.Put(std::int32_t{0});
    m.Put(std::int32_t{1});
    m.Put(std::int32_t{2});
    for (const std::string name : {"/env/decal_a.dds", "/env/decal_a_normals.dds"}) {
      m.Put(static_cast<std::int32_t>(name.size()));
      m.mBytes += name;
    }
    m.Zeros(11 * 4 + 4);
    m.Put(std::uint32_t{1}); // one group, two members
    m.Put(std::int32_t{0});
    m.Str("group");
    m.Put(std::int32_t{2});
    m.Zeros(8);
    m.Zeros(8);
    m.Put(std::int32_t{0}); // legacy records
    for (int sheet = 0; sheet < 2; ++sheet) {
      m.Put(std::uint32_t{5});
      m.Zeros(5);
    }
    m.Put(std::int32_t{1}); // one water map
    m.Put(std::uint32_t{7});
    m.Zeros(7);
    m.Zeros(3 * (kSide / 2) * (kSide / 2));
    m.Zeros(kSide * kSide);
    if (withSky) {
      m.Put(256.0f);
      m.Put(0.0f);
      m.Put(256.0f);
      m.Put(10.0f);   // horizon height
      m.Put(2343.0f); // scale
      m.Put(1.25f);   // subtract height
      m.Put(std::int32_t{16});
      m.Put(std::int32_t{6});
      m.Put(174.5f); // zenith height
      m.Put(0.1f);
      m.Put(0.2f);
      m.Put(0.3f);
      m.Put(0.4f);
      m.Put(0.5f);
      m.Put(0.6f);
      m.Put(0.7f); // decal glow
      m.Str("/textures/environment/sky_albedo.dds");
      m.Str("/textures/environment/sky_glow.dds");
      m.Put(std::int32_t{2});
      m.Zeros(2 * 0x28);
      m.Str("");
      m.Str("");
      m.Str("");
      m.Put(1.8f);
      m.Put(0.9f);
      m.Put(0.8f);
      m.Put(0.7f);
      m.Str("/textures/environment/cirrus.dds");
      m.Put(std::int32_t{4});
      m.Zeros(4 * 20);
    }
    return m.mBytes;
  }

  TEST(
    Looks,
    ReadsLightingWaterAndSkyFromAMap
  )
  {
    Look look;
    std::string error;
    ASSERT_TRUE(LookFromScmap(SmallMap(true), look, error)) << error;
    EXPECT_FLOAT_EQ(look.lighting.multiplier, 1.0f);
    EXPECT_FLOAT_EQ(look.lighting.sunColor[0], 8.0f) << "the eighth of the 23 lighting floats";
    EXPECT_FLOAT_EQ(look.lighting.fogEnd, 23.0f);
    ASSERT_EQ(look.cubes.size(), 1U);
    EXPECT_EQ(look.cubes[0].first, "<default>");
    EXPECT_TRUE(look.water.enabled);
    EXPECT_FLOAT_EQ(look.water.elevation, 17.5f);
    EXPECT_FLOAT_EQ(look.water.shader.mWaterColor[0], 100.0f);
    EXPECT_FLOAT_EQ(look.water.shader.mSunShininess, 110.0f) << "the eleventh header float";
    EXPECT_FLOAT_EQ(look.water.shader.mSunGlow, 119.0f);
    EXPECT_EQ(look.water.textures[1], "/textures/engine/waterramp.dds");
    EXPECT_FLOAT_EQ(look.water.shader.mNormalRepeatRate[3], 203.0f);
    EXPECT_FLOAT_EQ(look.water.shader.mNormal4Movement[0], 3.5f);
    EXPECT_EQ(look.water.textures[5], "/textures/engine/waves3.dds");
    ASSERT_TRUE(look.hasSky) << "the walk reached the sky past the waves, texturing, decals and masks";
    EXPECT_FLOAT_EQ(look.sky.scale, 2343.0f);
    EXPECT_EQ(look.sky.subdivisionsAxis, 16);
    EXPECT_FLOAT_EQ(look.sky.zenithColor[2], 0.6f);
    EXPECT_FLOAT_EQ(look.sky.decalGlow, 0.7f);
    EXPECT_EQ(look.sky.planets.size(), 2U);
    EXPECT_EQ(look.sky.cirrusTexture, "/textures/environment/cirrus.dds");
  }

  TEST(
    Looks,
    AFileWithoutASkyKeepsTheRest
  )
  {
    Look look;
    std::string error;
    ASSERT_TRUE(LookFromScmap(SmallMap(false), look, error)) << error;
    EXPECT_FALSE(look.hasSky);
    EXPECT_FLOAT_EQ(look.water.shader.mSunGlow, 119.0f);
    EXPECT_FALSE(LookFromScmap("Map\x1a", look, error));
    EXPECT_FALSE(LookFromScmap("not a map", look, error));
  }

  TEST(
    Looks,
    BlendMixesNumbersAndSwitchesNamesAtHalf
  )
  {
    Look from;
    Look to;
    std::string error;
    ASSERT_TRUE(LookFromScmap(SmallMap(true), to, error));
    from.lighting.multiplier = 3.0f;
    from.water.textures[1] = "/old/ramp.dds";
    from.water.elevation = 40.0f;
    const Look quarter = BlendLook(from, to, 0.25f, kLookAll);
    EXPECT_FLOAT_EQ(quarter.lighting.multiplier, 2.5f);
    EXPECT_EQ(quarter.water.textures[1], "/old/ramp.dds") << "names switch at one half";
    EXPECT_FLOAT_EQ(quarter.water.elevation, 40.0f) << "levels are never taken";
    const Look most = BlendLook(from, to, 0.75f, kLookAll);
    EXPECT_EQ(most.water.textures[1], "/textures/engine/waterramp.dds");
    EXPECT_EQ(most.sky.planets.size(), 2U);
    EXPECT_TRUE(most.hasSky);
  }

  TEST(
    Looks,
    SectionsChooseWhatIsTaken
  )
  {
    Look from;
    Look to;
    std::string error;
    ASSERT_TRUE(LookFromScmap(SmallMap(true), to, error));
    const Look light = BlendLook(from, to, 1.0f, kLookLighting);
    EXPECT_FLOAT_EQ(light.lighting.fogEnd, 23.0f);
    EXPECT_FLOAT_EQ(light.water.shader.mWaterColor[0], 0.0f) << "the water stays";
    EXPECT_FALSE(light.hasSky);
    const Look water = BlendLook(from, to, 1.0f, kLookWater);
    EXPECT_FLOAT_EQ(water.water.shader.mWaterColor[0], 100.0f);
    EXPECT_FLOAT_EQ(water.water.shader.mNormalRepeatRate[0], 0.0f) << "the waves are their own section";
    const Look waves = BlendLook(from, to, 1.0f, kLookWaves);
    EXPECT_FLOAT_EQ(waves.water.shader.mNormalRepeatRate[0], 200.0f);
    EXPECT_EQ(waves.water.textures[2], "/textures/engine/waves0.dds");
    const Look sky = BlendLook(from, to, 1.0f, kLookSky);
    EXPECT_TRUE(sky.hasSky);
    EXPECT_FLOAT_EQ(sky.sky.zenithHeight, 174.5f);
    EXPECT_FLOAT_EQ(sky.lighting.multiplier, from.lighting.multiplier);
  }
} // namespace
