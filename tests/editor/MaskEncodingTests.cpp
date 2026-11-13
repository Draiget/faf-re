// Texture masks are stored for the map's terrain shader (src/editor/tools/EdMaskBrush.h): most of FAF's terrain
// shaders read a mask byte m as saturate(2m - 1), TerrainPBR reads it as it is, and the Terrain1xx/2xx shaders read
// stratum 8 (the second mask's alpha) as it is. The brush works in the weight that shows and stores the byte for it.

#include "editor/tools/EdMaskBrush.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <vector>

namespace
{
  using faf::editor::ApplyMaskBrush;
  using faf::editor::CheckMaskRange;
  using faf::editor::MaskByte;
  using faf::editor::MaskCoverage;
  using faf::editor::MaskStoredFor;
  using faf::editor::MaskWeight;
  using faf::editor::RemappedStrata;
  using faf::editor::WithMaskByte;

  TEST(
    MaskEncoding,
    ShadersSayWhichStrataAreRemapped
  )
  {
    // Every composite technique of FAF's effects/terrain.fx, by the halfRange argument its albedo shader gets.
    EXPECT_EQ(RemappedStrata("TTerrain"), 0xFF) << "the original shader reads every stratum through 2m-1";
    EXPECT_EQ(RemappedStrata("TTerrainXP"), 0xFF);
    EXPECT_EQ(RemappedStrata("TTerrainGlow"), 0xFF);
    EXPECT_EQ(RemappedStrata("TTerrainXPExt"), 0xFF) << "Terrain000AlbedoPS(true)";
    EXPECT_EQ(RemappedStrata("Terrain000"), 0x00) << "Terrain000AlbedoPS(false): the full range";
    EXPECT_EQ(RemappedStrata("Terrain050"), 0xFF) << "Terrain000AlbedoPS(true)";
    EXPECT_EQ(RemappedStrata("Terrain001"), 0x00);
    EXPECT_EQ(RemappedStrata("Terrain051"), 0xFF);
    EXPECT_EQ(RemappedStrata("Terrain101B"), 0x00) << "Terrain100BAlbedoPS(false, 1)";
    EXPECT_EQ(RemappedStrata("Terrain151"), 0x7F) << "half range, stratum 8 as it is";
    EXPECT_EQ(RemappedStrata("terrain250"), 0x7F) << "names compare without case";
    EXPECT_EQ(RemappedStrata("Terrain252B"), 0x7F);
    EXPECT_EQ(RemappedStrata("Terrain200"), 0x00);
    EXPECT_EQ(RemappedStrata("Terrain301"), 0xFF) << "Terrain301AlbedoPS(true)";
    EXPECT_EQ(RemappedStrata("TerrainPBR"), 0x00) << "PBR reads masks as they are";
    EXPECT_EQ(RemappedStrata("SomethingNew"), 0xFF) << "an unknown shader: as most do";
    EXPECT_EQ(RemappedStrata("Terrain"), 0xFF) << "too short to be a numbered shader";
  }

  TEST(
    MaskEncoding,
    WeightsAndBytesRoundTrip
  )
  {
    EXPECT_FLOAT_EQ(MaskWeight(0, true), 0.0f);
    EXPECT_FLOAT_EQ(MaskWeight(127, true), 0.0f) << "half and below shows nothing";
    EXPECT_FLOAT_EQ(MaskWeight(128, true), 1.0f);
    EXPECT_FLOAT_EQ(MaskWeight(255, true), 255.0f);
    EXPECT_FLOAT_EQ(MaskWeight(200, false), 200.0f);
    for (int w = 0; w <= 255; ++w) {
      const std::uint8_t remapped = MaskStoredFor(static_cast<float>(w), true, 0);
      const int shown = static_cast<int>(MaskWeight(remapped, true) + 0.5f);
      EXPECT_LE(std::abs(shown - w), 1) << "remapped weight " << w << " stored as " << int(remapped);
      EXPECT_EQ(MaskStoredFor(static_cast<float>(w), false, 0), w) << "linear: the weight is the byte";
    }
    EXPECT_EQ(MaskStoredFor(0.0f, true, 255), 127) << "a remapped zero is stored as 127";
    EXPECT_EQ(MaskStoredFor(0.0f, true, 40), 40) << "a byte that already shows zero stays";
    EXPECT_EQ(MaskStoredFor(255.0f, true, 255), 255);
  }

  TEST(
    MaskEncoding,
    MasksMadeForAnotherRangeAreCounted
  )
  {
    std::vector<std::uint64_t> texels(4, 0);
    texels[0] = WithMaskByte(0, 0, 100); // hidden under 2m-1
    texels[1] = WithMaskByte(0, 0, 200); // shows
    texels[2] = WithMaskByte(0, 7, 60);  // stratum 8: hidden under TTerrain, shown under Terrain151
    texels[3] = WithMaskByte(0, 3, 127); // hidden
    const auto all = CheckMaskRange(texels.data(), texels.size(), 0xFF);
    EXPECT_EQ(all.hidden[0], 1);
    EXPECT_EQ(all.shown[0], 1);
    EXPECT_FALSE(all.PaintedForAnotherRange(0)) << "hidden edges next to paint that shows: GPG's own maps do that";
    EXPECT_TRUE(all.PaintedForAnotherRange(3)) << "paint and none of it shows";
    EXPECT_TRUE(all.PaintedForAnotherRange(7));
    EXPECT_FALSE(all.PaintedForAnotherRange(5)) << "no paint at all";
    EXPECT_EQ(all.Total(), 2);
    EXPECT_EQ(CheckMaskRange(texels.data(), texels.size(), 0x7F).Total(), 1) << "Terrain151 shows stratum 8";
    EXPECT_EQ(CheckMaskRange(texels.data(), texels.size(), 0x00).Total(), 0) << "PBR: nothing hidden";
  }

  TEST(
    MaskEncoding,
    CoverageCountsWhatShows
  )
  {
    std::vector<std::uint64_t> texels(2, 0);
    texels[0] = WithMaskByte(0, 0, 127);
    texels[1] = WithMaskByte(0, 0, 255);
    float linear[8] = {};
    float remapped[8] = {};
    MaskCoverage(texels.data(), texels.size(), linear, 0x00);
    MaskCoverage(texels.data(), texels.size(), remapped, 0xFF);
    EXPECT_NEAR(linear[0], (127.0f + 255.0f) / 510.0f, 1e-4f);
    EXPECT_NEAR(remapped[0], 0.5f, 1e-4f) << "127 shows nothing, 255 shows all";
  }

  TEST(
    MaskEncoding,
    TheBrushPaintsTheWeightThatShows
  )
  {
    // One remapped texel at 0: a full-strength paint stroke must reach a byte above 127, or nothing would show.
    std::vector<std::uint16_t> heights(9 * 9, 2560);
    std::vector<std::uint64_t> texels(4 * 4, 0);
    faf::editor::MaskBrush brush;
    brush.layer = 2;
    brush.mode = faf::editor::MaskBrushMode::Paint;
    brush.shape.radius = 8.0f;
    brush.shape.strength = 1.0f;
    brush.remapped = 0xFF;
    for (int i = 0; i < 40; ++i) {
      brush.step = static_cast<std::uint32_t>(i + 1);
      (void)ApplyMaskBrush(texels.data(), 4, 4, {heights.data(), 9, 9}, 4.0f, 4.0f, brush, 0.1f);
    }
    EXPECT_EQ(MaskByte(texels[5], 2), 255) << "painted to full weight";
    EXPECT_FLOAT_EQ(MaskWeight(MaskByte(texels[5], 2), true), 255.0f);
  }
} // namespace
