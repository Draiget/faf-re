// What a texture slot holds under a terrain shader (src/editor/tools/EdShaderSlots.cpp), as FAF's terrain.fx lays them
// out.

#include "editor/tools/EdShaderSlots.h"

#include <gtest/gtest.h>

namespace
{
  using faf::editor::ShaderSlotUseOf;

  TEST(
    ShaderSlots,
    GpgShadersHaveStrataOnly
  )
  {
    for (int slot = 0; slot < 10; ++slot) {
      EXPECT_TRUE(ShaderSlotUseOf("TTerrainXP", slot).text.empty());
      EXPECT_TRUE(ShaderSlotUseOf("TTerrain", slot).text.empty());
    }
  }

  TEST(
    ShaderSlots,
    TheNumberedShadersKeepStratum8AndTheUpperSlot
  )
  {
    // 1XX and 2XX: stratum 8 (S7) map-wide, the upper slot the layers' height and roughness.
    EXPECT_TRUE(ShaderSlotUseOf("Terrain250", 8).mapWide);
    EXPECT_TRUE(ShaderSlotUseOf("Terrain101B", 9).mapWide);
    EXPECT_TRUE(ShaderSlotUseOf("Terrain101B", 3).text.empty());
    // 000/050 (and TTerrainXPExt): a macrotexture; 001/051: a specular map; stratum 8 map-wide still.
    EXPECT_NE(ShaderSlotUseOf("Terrain050", 9).text.find("macrotexture"), std::string::npos);
    EXPECT_NE(ShaderSlotUseOf("TTerrainXPExt", 9).text.find("macrotexture"), std::string::npos);
    EXPECT_NE(ShaderSlotUseOf("Terrain001", 9).text.find("specular"), std::string::npos);
    EXPECT_TRUE(ShaderSlotUseOf("Terrain001", 8).mapWide);
    // 301 and PBR: stratum 8 a stratum again, the upper slot the map's normals, water depth and shadow.
    EXPECT_FALSE(ShaderSlotUseOf("Terrain301", 8).mapWide);
    EXPECT_TRUE(ShaderSlotUseOf("TerrainPBR", 9).mapWide);
    // Not a numbered shader.
    EXPECT_TRUE(ShaderSlotUseOf("Terrain", 8).text.empty());
    EXPECT_TRUE(ShaderSlotUseOf("Terrain10", 8).text.empty());
  }

  TEST(
    ShaderSlots,
    MapWideOnlyAboveTheMapsSize
  )
  {
    // terrain.fx: a scale of 1024 on a 512-unit map is a tile value of 0.5, under 1: map-wide.
    EXPECT_TRUE(faf::editor::MapWideOn(1024.0f, 512.0f));
    EXPECT_FALSE(faf::editor::MapWideOn(4.0f, 512.0f));
    EXPECT_FALSE(faf::editor::MapWideOn(512.0f, 512.0f));
  }
} // namespace
