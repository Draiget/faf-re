// Tile sizes from texel density (src/editor/tools/EdTexScale.cpp, FAF Studio's texscale.lua) and texture sets
// (src/editor/tools/EdTextureSets.cpp, its texsets.lua).

#include "editor/tools/EdTexScale.h"
#include "editor/tools/EdTextureSets.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace
{
  using namespace faf::editor;

  TEST(
    TextureSets,
    TilesFromTexelDensity
  )
  {
    EXPECT_FLOAT_EQ(TileForPixels(1024), 21.0f) << "1024 / 48.3 = 21.2";
    EXPECT_FLOAT_EQ(TileForPixels(2048), 42.5f);
    EXPECT_FLOAT_EQ(TileForPixels(512), 20.0f) << "small textures aren't tiled densely";
    EXPECT_FLOAT_EQ(TileForPixels(4096), 64.0f) << "at most 64";
    EXPECT_FLOAT_EQ(TileForPixels(0), 21.0f) << "unreadable: as 1024";
    EXPECT_FLOAT_EQ(MacroTile(21.0f), 144.0f) << "21 * phi^4, nearest 128, not a whole ratio";
    EXPECT_FLOAT_EQ(DecorrelatedTile(10.0f, 1), 16.0f);
    EXPECT_TRUE(IsDefaultTile(4.0f, 21.0f));
    EXPECT_TRUE(IsDefaultTile(21.0f, 21.0f));
    EXPECT_FALSE(IsDefaultTile(15.0f, 21.0f));
    unsigned char header[128] = {'D', 'D', 'S', ' '};
    const std::uint32_t width = 2048;
    std::memcpy(header + 16, &width, 4);
    EXPECT_EQ(DdsWidth(header, sizeof(header)), 2048);
    EXPECT_EQ(DdsWidth("PNG ", 4), 0);
  }

  TEST(
    TextureSets,
    EachShaderHasItsLayout
  )
  {
    const auto at = [](const std::array<int, 9>& layout, const GroundKind kind) {
      return layout[static_cast<std::size_t>(kind)];
    };
    const auto eight = ThemeLayout(8, false);
    EXPECT_EQ(at(eight, GroundKind::Grass), 1);
    EXPECT_EQ(at(eight, GroundKind::Snow), 8);
    const auto seven = ThemeLayout(7, false);
    EXPECT_EQ(at(seven, GroundKind::DarkRock), 0) << "no dark rock with 7 layers";
    EXPECT_EQ(at(seven, GroundKind::Snow), 7);
    const auto biplanar = ThemeLayout(7, true);
    EXPECT_EQ(at(biplanar, GroundKind::Rock), 3) << "rock drawn from the side";
    EXPECT_EQ(at(biplanar, GroundKind::HighRock), 4);
    const auto four = ThemeLayout(4, false);
    EXPECT_EQ(at(four, GroundKind::Grass), 0) << "TTerrain: grass is the base";
    EXPECT_EQ(at(four, GroundKind::Rock), 1);
  }

  TEST(
    TextureSets,
    AThemeFillsTheLayersWithItsFirstExistingTextures
  )
  {
    const TextureTheme& valley = TextureThemes()[1];
    ASSERT_STREQ(valley.id, "valley");
    // The game has every Evergreen (1) texture but none of Evergreen 2's; every texture is 1024 px.
    const auto exists = [](const std::string& path) {
      return path.rfind("/env/Evergreen/", 0) == 0;
    };
    const auto pixels = [](const std::string&) {
      return 1024;
    };
    const std::vector<ThemeSlot> slots = ThemeSlots(valley, 8, false, true, exists, pixels);
    ASSERT_EQ(slots.size(), 10U) << "the base, the eight kinds (each has an Evergreen candidate last) and the Upper";
    EXPECT_EQ(slots[0].slot, 0);
    EXPECT_EQ(slots[0].albedo, "/env/Evergreen/layers/grass001_albedo.dds") << "the first candidate that exists";
    EXPECT_FLOAT_EQ(slots[0].size, 21.0f);
    EXPECT_EQ(slots.back().slot, 9);
    EXPECT_FLOAT_EQ(slots.back().size, 144.0f) << "the macrotexture's tile";
    // Without an overlay Upper (the PBR shaders) and with 7 layers.
    const std::vector<ThemeSlot> seven = ThemeSlots(valley, 7, false, false, [](const std::string&) {
      return true;
    }, pixels);
    for (const ThemeSlot& s : seven) {
      EXPECT_LE(s.slot, 7);
    }
  }
} // namespace
