// Convert layers (src/editor/tools/EdLayerConvert.cpp, FAF Studio's stratumconv.lua, the masks part): the paint
// re-encoded for the target's range, the layers the target can't draw moved, merged or dropped, layer 8 made a
// neutral roughness multiplier for the 1xx / 2xx shaders, the cliff layers moved to layers 3 and 4 for the biplanar
// ones, and the conversions the editor refuses.

#include "editor/tools/EdLayerConvert.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

namespace
{
  using faf::editor::ConvertMasks;
  using faf::editor::LayerConvertOptions;
  using faf::editor::LayerConvertPlan;
  using faf::editor::LayerPaint;
  using faf::editor::LostLayers;
  using faf::editor::MaskByte;
  using faf::editor::PlanLayerConversion;
  using faf::editor::WithMaskByte;

  /** Paint with these layers' strongest bytes (0-7), everything else empty and untextured. */
  LayerPaint Painted(
    const std::vector<std::pair<int, int>>& strongest
  )
  {
    LayerPaint paint;
    for (const auto& [layer, byte] : strongest) {
      paint.strongest[static_cast<std::size_t>(layer)] = byte;
      paint.textured[static_cast<std::size_t>(layer)] = true;
    }
    return paint;
  }

  std::uint64_t Texel(
    const std::vector<std::pair<int, int>>& bytes
  )
  {
    std::uint64_t texel = 0;
    for (const auto& [layer, byte] : bytes) {
      texel = WithMaskByte(texel, layer, static_cast<std::uint8_t>(byte));
    }
    return texel;
  }

  TEST(
    LayerConvert,
    LayerListsReadLikeSentences
  )
  {
    EXPECT_EQ(faf::editor::LayerListText({0}), "layer 1");
    EXPECT_EQ(faf::editor::LayerListText({4, 7}), "layers 5 and 8");
    EXPECT_EQ(faf::editor::LayerListText({0, 1, 2, 3, 4, 5, 6}), "layers 1-7");
    EXPECT_EQ(faf::editor::LayerListText({0, 1, 2, 4, 7}), "layers 1-3, 5 and 8");
  }

  TEST(
    LayerConvert,
    TheRangeIsReEncodedSoThePaintLooksTheSame
  )
  {
    const LayerConvertOptions options;
    // TTerrainXP (half range) to Terrain000 (full): 191 shows 127, 100 shows nothing.
    const LayerConvertPlan toFull = PlanLayerConversion("TTerrainXP", "Terrain000", Painted({{0, 255}}), options);
    ASSERT_TRUE(toFull.refused.empty()) << toFull.refused;
    std::vector<std::uint64_t> texels = {Texel({{0, 191}, {1, 100}}), Texel({{0, 255}})};
    EXPECT_EQ(ConvertMasks(texels.data(), texels.size(), toFull, options), 1u) << "255 is full weight in either range";
    EXPECT_EQ(MaskByte(texels[0], 0), 127);
    EXPECT_EQ(MaskByte(texels[0], 1), 0);
    EXPECT_EQ(MaskByte(texels[1], 0), 255);
    // And back to the half range (Terrain050): within a step.
    const LayerConvertPlan toHalf = PlanLayerConversion("Terrain000", "Terrain050", Painted({{0, 255}}), options);
    (void)ConvertMasks(texels.data(), texels.size(), toHalf, options);
    EXPECT_NEAR(MaskByte(texels[0], 0), 191, 1);
    EXPECT_EQ(MaskByte(texels[1], 0), 255);
    // The same range: bytes kept exactly.
    const LayerConvertPlan same = PlanLayerConversion("TTerrainXP", "Terrain050", Painted({{0, 255}}), options);
    std::vector<std::uint64_t> exact = {Texel({{0, 140}, {2, 77}})};
    EXPECT_EQ(ConvertMasks(exact.data(), exact.size(), same, options), 0u);
  }

  TEST(
    LayerConvert,
    PaintTheTargetCannotDrawIsMovedMergedOrDropped
  )
  {
    // TTerrainXP paints layer 8; Terrain050 paints 1-7. Layers 1 and 2 hold paint, layer 5 is free.
    const LayerPaint paint = Painted({{0, 255}, {1, 255}, {7, 255}});
    const std::vector<std::uint64_t> start = {Texel({{0, 200}, {1, 150}, {7, 255}})};

    LayerConvertOptions move;
    const LayerConvertPlan moved = PlanLayerConversion("TTerrainXP", "Terrain050", paint, move);
    ASSERT_EQ(moved.lost, std::vector<int>({7}));
    EXPECT_EQ(moved.arrangement[2], 7) << "the first free layer (untextured) takes layer 8";
    std::vector<std::uint64_t> texels = start;
    (void)ConvertMasks(texels.data(), texels.size(), moved, move);
    EXPECT_EQ(MaskByte(texels[0], 2), 255) << "layer 8's paint, now on layer 3";
    EXPECT_EQ(MaskByte(texels[0], 0), 200);

    LayerConvertOptions merge;
    merge.lost = LostLayers::Merge;
    merge.mergeInto = 1;
    texels = start;
    (void)ConvertMasks(
      texels.data(), texels.size(), PlanLayerConversion("TTerrainXP", "Terrain050", paint, merge), merge
    );
    EXPECT_EQ(MaskByte(texels[0], 1), 255) << "the stronger of layers 2 and 8";
    EXPECT_EQ(MaskByte(texels[0], 7), 0);

    LayerConvertOptions drop;
    drop.lost = LostLayers::Drop;
    texels = start;
    const LayerConvertPlan dropped = PlanLayerConversion("TTerrainXP", "Terrain050", paint, drop);
    (void)ConvertMasks(texels.data(), texels.size(), dropped, drop);
    EXPECT_EQ(MaskByte(texels[0], 7), 0);
    EXPECT_EQ(MaskByte(texels[0], 1), 150);
    EXPECT_FALSE(dropped.warnings.empty());
  }

  TEST(
    LayerConvert,
    LayerEightBecomesANeutralRoughnessMultiplier
  )
  {
    const LayerConvertOptions options;
    const LayerConvertPlan plan = PlanLayerConversion("Terrain050", "Terrain151", Painted({{0, 255}}), options);
    EXPECT_TRUE(plan.toRoughLayer8);
    std::vector<std::uint64_t> texels = {Texel({{0, 255}}), 0};
    (void)ConvertMasks(texels.data(), texels.size(), plan, options);
    EXPECT_EQ(MaskByte(texels[0], 7), 128);
    EXPECT_EQ(MaskByte(texels[1], 7), 128);
    EXPECT_EQ(MaskByte(texels[0], 0), 255) << "half range to half range: as it was";
  }

  TEST(
    LayerConvert,
    BiplanarShadersGetTheCliffLayersOnThreeAndFour
  )
  {
    LayerPaint paint = Painted({{0, 255}, {2, 255}, {5, 255}});
    paint.slopeDegrees[0] = 4.0f;
    paint.slopeDegrees[2] = 6.0f;  // flat-ground paint on layer 3
    paint.slopeDegrees[5] = 35.0f; // cliffs on layer 6
    const LayerConvertOptions options;
    const LayerConvertPlan plan = PlanLayerConversion("Terrain000", "Terrain101B", paint, options);
    ASSERT_TRUE(plan.toBiplanar);
    EXPECT_EQ(plan.arrangement[2], 5) << "layer 6's cliffs to layer 3";
    EXPECT_EQ(plan.arrangement[5], 2) << "and layer 3 to layer 6";
    std::vector<std::uint64_t> texels = {Texel({{2, 90}, {5, 255}})};
    (void)ConvertMasks(texels.data(), texels.size(), plan, options);
    EXPECT_EQ(MaskByte(texels[0], 2), 255);
    EXPECT_EQ(MaskByte(texels[0], 5), 90);
  }

  TEST(
    LayerConvert,
    SomeConversionsAreRefused
  )
  {
    const LayerConvertOptions options;
    EXPECT_FALSE(PlanLayerConversion("TTerrainXP", "TTerrainXP", {}, options).refused.empty());
    EXPECT_FALSE(PlanLayerConversion("TTerrainXP", "Terrain301", {}, options).refused.empty());
    EXPECT_FALSE(PlanLayerConversion("Terrain301", "Terrain250", {}, options).refused.empty());
    EXPECT_FALSE(PlanLayerConversion("TerrainFuture9", "Terrain250", {}, options).refused.empty());
    EXPECT_TRUE(PlanLayerConversion("TTerrain", "TTerrainXP", {}, options).refused.empty());
  }

  TEST(
    LayerConvert,
    PaintSlopesAreReadFromTheGround
  )
  {
    // 65 x 65 heights rising 1:1 towards +x on the right half, flat on the left; 32 x 32 texels.
    std::vector<std::uint16_t> heights(65 * 65);
    for (int z = 0; z < 65; ++z) {
      for (int x = 0; x < 65; ++x) {
        heights[static_cast<std::size_t>(z * 65 + x)] = static_cast<std::uint16_t>(2560 + std::max(0, x - 32) * 128);
      }
    }
    std::vector<std::uint64_t> texels(32 * 32, 0);
    for (int z = 0; z < 32; ++z) {
      for (int x = 0; x < 32; ++x) {
        const bool right = x >= 18;
        const bool left = x <= 13;
        texels[static_cast<std::size_t>(z * 32 + x)] = Texel({{0, left ? 255 : 0}, {1, right ? 255 : 0}});
      }
    }
    const LayerPaint paint = faf::editor::ReadLayerPaint(texels.data(), 32, 32, {heights.data(), 65, 65}, 0x00, {});
    EXPECT_NEAR(paint.slopeDegrees[0], 0.0f, 0.5f);
    EXPECT_NEAR(paint.slopeDegrees[1], 45.0f, 1.0f);
    EXPECT_EQ(paint.strongest[0], 255);
    EXPECT_EQ(paint.strongest[2], 0);
  }
} // namespace
