// The map editor's texture-layer brush (src/editor/tools/EdMaskBrush.cpp): mirrored masks stay identical
// after random strokes, Paint and Erase reach their ends even when weak, Paint lowers the layers above,
// limits and rules follow the ground, and the mask history undoes byte for byte.

#include "editor/tools/EdMaskBrush.h"
#include "editor/undo/EdHeightHistory.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <random>
#include <vector>

namespace
{
  using faf::editor::ApplyMaskBrush;
  using faf::editor::MaskBrush;
  using faf::editor::MaskBrushMode;
  using faf::editor::MaskByte;
  using faf::editor::MaskTerrain;
  using faf::editor::SampleRect;
  using faf::editor::Symmetry;

  constexpr int kMask = 32;  // mask texels
  constexpr int kField = 65; // height samples: two per texel

  struct World
  {
    std::vector<std::uint16_t> heights = std::vector<std::uint16_t>(kField * kField, 2560); // 20 units
    std::vector<std::uint64_t> texels = std::vector<std::uint64_t>(kMask * kMask, 0);
    [[nodiscard]] MaskTerrain Terrain() const { return {heights.data(), kField, kField}; }
    [[nodiscard]] std::uint64_t At(const int x, const int z) const { return texels[static_cast<std::size_t>(z * kMask + x)]; }
  };

  void Step(World& world, MaskBrush brush, const float x, const float z, const float seconds)
  {
    static std::uint32_t steps = 0;
    brush.step = ++steps;
    (void)ApplyMaskBrush(world.texels.data(), kMask, kMask, world.Terrain(), x, z, brush, seconds);
  }

  class EveryMaskSymmetry : public ::testing::TestWithParam<Symmetry>
  {};

  TEST_P(EveryMaskSymmetry, MirroredMasksStayIdentical)
  {
    World world;
    std::mt19937 random(11u + static_cast<unsigned>(GetParam()));
    std::uniform_real_distribution<float> along(0.0f, 64.0f);
    std::uniform_real_distribution<float> unit(0.05f, 1.0f);
    std::uniform_int_distribution<int> layer(0, 7);
    std::uniform_int_distribution<int> mode(0, 2);
    for (int stroke = 0; stroke < 150; ++stroke) {
      MaskBrush brush;
      brush.shape.symmetry = GetParam();
      brush.shape.radius = 2.0f + unit(random) * 10.0f;
      brush.shape.strength = unit(random);
      brush.shape.falloff = unit(random);
      brush.mode = static_cast<MaskBrushMode>(mode(random));
      brush.layer = layer(random);
      brush.lowerAbove = stroke % 2 == 0;
      Step(world, brush, along(random), along(random), 0.05f);
    }
    for (int z = 0; z < kMask; ++z) {
      for (int x = 0; x < kMask; ++x) {
        int cx[faf::editor::kMaxSymmetryCopies];
        int cz[faf::editor::kMaxSymmetryCopies];
        const int n = faf::editor::SymmetricSamples(GetParam(), 3, kMask, kMask, x, z, cx, cz);
        for (int i = 1; i < n; ++i) {
          ASSERT_EQ(world.At(cx[i], cz[i]), world.At(x, z)) << x << "," << z;
        }
      }
    }
  }

  INSTANTIATE_TEST_SUITE_P(
    MaskBrush, EveryMaskSymmetry,
    ::testing::Values(Symmetry::LeftRight, Symmetry::TopBottom, Symmetry::DiagonalBack, Symmetry::DiagonalForward, Symmetry::HalfTurn,
                      Symmetry::BothAxes, Symmetry::BothDiagonals, Symmetry::QuarterTurns)
  );

  TEST(MaskBrush, PaintAndEraseReachTheirEndsEvenWeak)
  {
    World world;
    MaskBrush brush;
    brush.layer = 3;
    brush.shape.radius = 8.0f;
    brush.shape.strength = 0.05f;
    for (int frame = 0; frame < 600; ++frame) {
      Step(world, brush, 32.0f, 32.0f, 1.0f / 60.0f);
    }
    EXPECT_EQ(MaskByte(world.At(15, 15), 3), 255);
    EXPECT_EQ(MaskByte(world.At(2, 2), 3), 0); // outside
    brush.mode = MaskBrushMode::Erase;
    for (int frame = 0; frame < 600; ++frame) {
      Step(world, brush, 32.0f, 32.0f, 1.0f / 60.0f);
    }
    EXPECT_EQ(MaskByte(world.At(15, 15), 3), 0);
  }

  TEST(MaskBrush, PaintLowersTheLayersAbove)
  {
    World world;
    for (std::uint64_t& texel : world.texels) {
      texel = faf::editor::WithMaskByte(texel, 5, 255);
    }
    MaskBrush brush;
    brush.layer = 2;
    brush.shape.radius = 8.0f;
    brush.shape.strength = 1.0f;
    Step(world, brush, 32.0f, 32.0f, 1.0f);
    EXPECT_EQ(MaskByte(world.At(15, 15), 2), 255);
    EXPECT_EQ(MaskByte(world.At(15, 15), 5), 0);
    brush.lowerAbove = false;
    brush.layer = 1;
    World kept;
    for (std::uint64_t& texel : kept.texels) {
      texel = faf::editor::WithMaskByte(texel, 5, 255);
    }
    Step(kept, brush, 32.0f, 32.0f, 1.0f);
    EXPECT_EQ(MaskByte(kept.At(15, 15), 5), 255);
  }

  TEST(MaskBrush, LimitsAndRulesFollowTheGround)
  {
    World world;
    // The left half high (60 units), the right half low (20).
    for (int z = 0; z < kField; ++z) {
      for (int x = 0; x < kField / 2; ++x) {
        world.heights[static_cast<std::size_t>(z * kField + x)] = 60 * 128;
      }
    }
    MaskBrush brush;
    brush.shape.radius = 40.0f;
    brush.shape.strength = 1.0f;
    brush.shape.limitHeight = true;
    brush.shape.limitLow = 50.0f * 128.0f;
    brush.shape.limitHigh = 70.0f * 128.0f;
    Step(world, brush, 32.0f, 32.0f, 1.0f);
    EXPECT_EQ(MaskByte(world.At(4, 16), 0), 255);
    EXPECT_EQ(MaskByte(world.At(28, 16), 0), 0);

    faf::editor::MaskRule rule;
    rule.layer = 6;
    rule.useHeight = true;
    rule.low = 0.0f;
    rule.high = 30.0f;
    (void)faf::editor::ApplyMaskRules(world.texels.data(), kMask, kMask, world.Terrain(), {rule});
    EXPECT_EQ(MaskByte(world.At(28, 16), 6), 255);
    EXPECT_EQ(MaskByte(world.At(4, 16), 6), 0);
  }

  TEST(MaskBrush, SymmetryCheckFindsAPlantedTexelAndRepairsIt)
  {
    for (const Symmetry symmetry : {Symmetry::LeftRight, Symmetry::BothDiagonals, Symmetry::QuarterTurns, Symmetry::NWay}) {
      World world;
      MaskBrush brush;
      brush.shape.symmetry = symmetry;
      brush.shape.radius = 12.0f;
      brush.layer = 2;
      Step(world, brush, 20.0f, 14.0f, 0.3f);
      EXPECT_EQ(faf::editor::CheckMaskSymmetry(world.texels.data(), kMask, kMask, symmetry, 3).differing, 0) << static_cast<int>(symmetry);
      std::uint64_t& planted = world.texels[static_cast<std::size_t>(3 * kMask + 25)];
      planted = faf::editor::WithMaskByte(planted, 6, 90);
      const faf::editor::MaskSymmetryReport report = faf::editor::CheckMaskSymmetry(world.texels.data(), kMask, kMask, symmetry, 3);
      EXPECT_GE(report.differing, 1) << static_cast<int>(symmetry);
      EXPECT_EQ(report.largest, 90) << static_cast<int>(symmetry);
      (void)faf::editor::MakeMasksSymmetric(world.texels.data(), kMask, kMask, symmetry, 3);
      EXPECT_EQ(faf::editor::CheckMaskSymmetry(world.texels.data(), kMask, kMask, symmetry, 3).differing, 0) << static_cast<int>(symmetry);
    }
  }

  TEST(MaskBrush, HistoryUndoesByteForByte)
  {
    World world;
    faf::editor::MaskHistory history;
    history.Reset(kMask, kMask);
    const std::vector<std::uint64_t> before = world.texels;
    MaskBrush brush;
    brush.layer = 4;
    brush.shape.radius = 10.0f;
    brush.shape.symmetry = Symmetry::BothAxes;
    history.BeginStroke();
    for (int frame = 0; frame < 30; ++frame) {
      for (const SampleRect& rect : faf::editor::MaskBrushRects(kMask, kMask, world.Terrain(), 20.0f, 24.0f, brush)) {
        history.BeforeWrite(world.texels.data(), rect);
      }
      Step(world, brush, 20.0f, 24.0f, 1.0f / 60.0f);
    }
    history.EndStroke(world.texels.data());
    const std::vector<std::uint64_t> after = world.texels;
    ASSERT_NE(after, before);
    std::vector<SampleRect> changed;
    ASSERT_TRUE(history.Undo(world.texels.data(), changed));
    EXPECT_EQ(world.texels, before);
    ASSERT_TRUE(history.Redo(world.texels.data(), changed));
    EXPECT_EQ(world.texels, after);
  }
} // namespace
