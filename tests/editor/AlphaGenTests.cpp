#include "editor/tools/EdAlphaGen.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>

namespace faf::editor
{
  namespace
  {
    constexpr std::size_t kCount = static_cast<std::size_t>(kAtlasTile) * kAtlasTile;

    /** A BGRA picture whose brightness is `f(x, z)` (0..255 grey). */
    template <typename F>
    std::vector<std::uint8_t> Grey(
      F f
    )
    {
      std::vector<std::uint8_t> out(kCount * 4);
      for (int z = 0; z < kAtlasTile; ++z) {
        for (int x = 0; x < kAtlasTile; ++x) {
          const auto v = static_cast<std::uint8_t>(std::clamp(f(x, z), 0, 255));
          const std::size_t at = (static_cast<std::size_t>(z) * kAtlasTile + x) * 4;
          out[at] = out[at + 1] = out[at + 2] = v;
          out[at + 3] = 255;
        }
      }
      return out;
    }

    float Sd(
      const std::vector<float>& v
    )
    {
      double mean = 0.0;
      for (const float x : v) {
        mean += x;
      }
      mean /= static_cast<double>(v.size());
      double sq = 0.0;
      for (const float x : v) {
        sq += (x - mean) * (x - mean);
      }
      return static_cast<float>(std::sqrt(sq / static_cast<double>(v.size())));
    }
  } // namespace

  TEST(
    AlphaGen,
    TileHeightHasTheSameContrastForEveryTextureAndTheKindsStep
  )
  {
    const AtlasSettings settings;
    std::string error;
    // A flat texture: the kind's height and roughness everywhere.
    AtlasTile flat;
    ASSERT_TRUE(MakeAtlasTile(
      Grey([](int, int) {
      return 120;
    }),
      {},
      GroundKind::Rock,
      settings,
      flat,
      error
    )) << error;
    EXPECT_NEAR(flat.height[1000], 0.5f + 0.20f, 1e-5f) << "rock stands 0.2 up";
    EXPECT_NEAR(flat.rough[1000], 0.88f, 1e-5f);
    // A faint and a strong stripe pattern get the same height contrast (0.16); bright is rougher-less (smoother).
    AtlasTile faint;
    AtlasTile strong;
    ASSERT_TRUE(MakeAtlasTile(
      Grey([](int x, int) {
      return 120 + (x % 8 < 4 ? 5 : -5);
    }),
      {},
      GroundKind::Grass,
      settings,
      faint,
      error
    ));
    ASSERT_TRUE(MakeAtlasTile(
      Grey([](int x, int) {
      return 120 + (x % 8 < 4 ? 80 : -80);
    }),
      {},
      GroundKind::Grass,
      settings,
      strong,
      error
    ));
    EXPECT_NEAR(Sd(faint.height), 0.16f, 0.005f);
    EXPECT_NEAR(Sd(strong.height), 0.16f, 0.005f);
    EXPECT_LT(strong.rough[0], strong.rough[4]) << "a bright spot is smoother";
    EXPECT_NEAR(strong.height[0] + strong.height[4], 2.0f * (0.5f - 0.12f), 1e-4f) << "grass sits 0.12 down";
    // A normal map's relief counts by `cavity`: a bump in its slopes raises the tile there.
    std::vector<std::uint8_t> normal(kCount * 4, 128);
    for (int z = 0; z < kAtlasTile; ++z) {
      for (int x = 0; x < kAtlasTile; ++x) {
        const float slope = std::sin(static_cast<float>(x) * 6.2831853f / kAtlasTile); // h = cos: n.x = -dh/dx = sin
        normal[(static_cast<std::size_t>(z) * kAtlasTile + x) * 4 + 2] =
          static_cast<std::uint8_t>(127.5f + slope * 60.0f);
      }
    }
    AtlasTile relief;
    AtlasSettings onlyRelief;
    onlyRelief.cavity = 1.0f;
    ASSERT_TRUE(MakeAtlasTile(
      Grey([](int, int) {
      return 120;
    }),
      normal,
      GroundKind::Unknown,
      onlyRelief,
      relief,
      error
    )) << error;
    EXPECT_NEAR(Sd(relief.height), 0.16f, 0.01f);
    EXPECT_GT(std::fabs(relief.height[0] - relief.height[kAtlasTile / 2]), 0.3f)
      << "a hill and a valley half a tile apart";
    EXPECT_FALSE(MakeAtlasTile(std::vector<std::uint8_t>(16), {}, GroundKind::Rock, settings, flat, error));
  }

  TEST(
    AtlasPack,
    TilesGoInTwoByTwoWithTheUpperFourInBlueAndAlpha
  )
  {
    AtlasTile a;
    a.height.assign(kCount, 0.9f);
    a.rough.assign(kCount, 0.5f);
    std::array<const AtlasTile*, 8> tiles{};
    tiles[1] = &a; // layer 1: top right, R and G
    tiles[6] = &a; // layer 6: bottom left (6 % 4 = 2), B and A
    std::array<GroundKind, 8> kinds{};
    kinds[3] = GroundKind::Rock;
    std::vector<float> rgba;
    PackAtlas(tiles, kinds, AtlasSettings{}, 1024, rgba);
    ASSERT_EQ(rgba.size(), 1024U * 1024U * 4U);
    const auto px = [&](const int x, const int z, const int c) {
      return rgba[(static_cast<std::size_t>(z) * 1024 + x) * 4 + c];
    };
    EXPECT_FLOAT_EQ(px(700, 100, 0), 0.5f) << "layer 1's roughness, top right, red";
    EXPECT_FLOAT_EQ(px(700, 100, 1), 0.9f) << "its height, green";
    EXPECT_FLOAT_EQ(px(100, 700, 2), 0.5f) << "layer 6, bottom left, blue";
    EXPECT_FLOAT_EQ(px(100, 700, 3), 0.9f);
    EXPECT_FLOAT_EQ(px(100, 100, 0), 0.65f) << "no texture: neutral roughness";
    EXPECT_FLOAT_EQ(px(700, 700, 1), 0.7f) << "layer 3 without a texture: rock's step";
    // A style fills the settings and the splat numbers.
    AtlasSettings s;
    float soft = 0.0f, contrast = 0.0f;
    ApplyAtlasStyle("patchy", s, soft, contrast);
    EXPECT_FLOAT_EQ(s.spread, 2.0f);
    EXPECT_FLOAT_EQ(contrast, 1.5f);
    s.spread = 1.3f;
    ApplyAtlasStyle("custom", s, soft, contrast);
    EXPECT_FLOAT_EQ(s.spread, 1.3f) << "custom keeps the numbers";
  }
} // namespace faf::editor
