// The terrain shader profiles of the shader browser (src/editor/tools/EdShaderProfiles.cpp, FAF Studio's shaders.lua):
// every composite technique of FAF's effects/terrain.fx gets its family, its painted layers, a full layer table and
// the mask range the brushes use; a shader the table doesn't know gets a plain entry.

#include "editor/tools/EdMaskBrush.h"
#include "editor/tools/EdShaderProfiles.h"

#include <gtest/gtest.h>

#include <string>

namespace
{
  using faf::editor::ShaderFamily;
  using faf::editor::ShaderProfileOf;

  // Every composite technique of FAF's effects/terrain.fx.
  constexpr const char* kTechniques[] = {
    "TTerrain",    "TTerrainXP",  "TTerrainGlow", "TerrainPBR",  "TTerrainXPExt", "Terrain050",  "Terrain001",
    "Terrain051",  "Terrain100",  "Terrain101",   "Terrain102",  "Terrain150",    "Terrain151",  "Terrain152",
    "Terrain100B", "Terrain101B", "Terrain102B",  "Terrain150B", "Terrain151B",   "Terrain152B", "Terrain200",
    "Terrain201",  "Terrain202",  "Terrain250",   "Terrain251",  "Terrain252",    "Terrain200B", "Terrain201B",
    "Terrain202B", "Terrain250B", "Terrain251B",  "Terrain252B", "Terrain301",    "Terrain000",
  };

  TEST(
    ShaderProfile,
    EveryTechniqueHasALayerTableAndTheBrushesRange
  )
  {
    for (const char* const name : kTechniques) {
      const faf::editor::ShaderProfile p = ShaderProfileOf(name);
      EXPECT_EQ(p.name, name);
      EXPECT_EQ(p.remapped, faf::editor::RemappedStrata(name)) << name << ": the browser and the brushes agree";
      EXPECT_FALSE(p.summary.empty()) << name;
      if (p.known) {
        EXPECT_EQ(p.rows.size(), 10u) << name << ": Base, layers 1-8, Upper";
      }
    }
  }

  TEST(
    ShaderProfile,
    FamiliesAndPaintedLayers
  )
  {
    EXPECT_EQ(ShaderProfileOf("TTerrain").painted, 4);
    EXPECT_EQ(ShaderProfileOf("TTerrainXP").painted, 8);
    EXPECT_EQ(ShaderProfileOf("TTerrainXP").family, ShaderFamily::Original);
    EXPECT_EQ(ShaderProfileOf("Terrain050").family, ShaderFamily::Extended);
    EXPECT_EQ(ShaderProfileOf("Terrain050").painted, 7);
    EXPECT_EQ(ShaderProfileOf("Terrain151").family, ShaderFamily::Pbr);
    EXPECT_EQ(ShaderProfileOf("Terrain252B").family, ShaderFamily::Splat);
    EXPECT_EQ(ShaderProfileOf("terrain252b").family, ShaderFamily::Splat) << "names compare without case";
    EXPECT_FALSE(ShaderProfileOf("Terrain301").convertible);
    EXPECT_EQ(ShaderProfileOf("TTerrain").rows[5].albedo, "not drawn") << "layer 5 under TTerrain";
  }

  TEST(
    ShaderProfile,
    BiplanarShadersPutCliffsOnLayersThreeAndFour
  )
  {
    const faf::editor::ShaderProfile b = ShaderProfileOf("Terrain151B");
    EXPECT_NE(b.rows[3].albedo.find("side"), std::string::npos) << b.rows[3].albedo;
    EXPECT_NE(b.rows[4].albedo.find("side"), std::string::npos);
    EXPECT_EQ(b.rows[5].albedo.find("side"), std::string::npos);
    EXPECT_NE(b.summary.find("biplanar"), std::string::npos);
    EXPECT_NE(b.summary.find("half mask range"), std::string::npos);
    EXPECT_NE(ShaderProfileOf("Terrain101").summary.find("full mask range"), std::string::npos);
  }

  TEST(
    ShaderProfile,
    AnUnknownShaderGetsAPlainEntry
  )
  {
    const faf::editor::ShaderProfile p = ShaderProfileOf("TerrainFuture9");
    EXPECT_FALSE(p.known);
    EXPECT_EQ(p.family, ShaderFamily::Older);
    EXPECT_FALSE(p.convertible);
    EXPECT_FALSE(p.instructions.empty());
  }
} // namespace
