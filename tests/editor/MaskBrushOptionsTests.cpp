// FAF Studio's mask brush options in the editor's mask brush (src/editor/tools/EdMaskBrush.cpp): a target weight, the
// per-stroke coverage model (no pile-up) beside build-up, Erase by coverage, scatter that stays the same at every
// copy, a minimum slope, and shaped masks read in the cursor's frame.

#include "editor/tools/EdMaskBrush.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

namespace
{
  using faf::editor::ApplyMaskBrush;
  using faf::editor::BrushShape;
  using faf::editor::MaskBrush;
  using faf::editor::MaskBrushMode;
  using faf::editor::MaskByte;
  using faf::editor::MaskStroke;
  using faf::editor::MaskTerrain;
  using faf::editor::Symmetry;

  constexpr int kMask = 32;  // texels
  constexpr int kField = 65; // height samples: two per texel

  struct World
  {
    std::vector<std::uint16_t> heights = std::vector<std::uint16_t>(kField * kField, 2560);
    std::vector<std::uint64_t> texels = std::vector<std::uint64_t>(kMask * kMask, 0);
    [[nodiscard]] MaskTerrain Terrain() const
    {
      return {heights.data(), kField, kField};
    }
    [[nodiscard]] int At(
      const int x,
      const int z,
      const int layer = 0
    ) const
    {
      return MaskByte(texels[static_cast<std::size_t>(z * kMask + x)], layer);
    }
  };

  MaskBrush Brush()
  {
    MaskBrush brush;
    brush.shape.radius = 10.0f;
    brush.shape.falloff = 0.2f;
    brush.shape.strength = 1.0f;
    brush.lowerAbove = false;
    return brush;
  }

  void Steps(
    World& world,
    const MaskBrush& start,
    const int steps,
    const float x = 32.0f,
    const float z = 32.0f,
    MaskStroke* const stroke = nullptr
  )
  {
    MaskBrush brush = start;
    for (int i = 0; i < steps; ++i) {
      brush.step = static_cast<std::uint32_t>(i + 1);
      (void)ApplyMaskBrush(world.texels.data(), kMask, kMask, world.Terrain(), x, z, brush, 1.0f / 60.0f, stroke);
    }
  }

  TEST(
    MaskBrushOptions,
    PaintStopsAtTheTarget
  )
  {
    World world;
    MaskBrush brush = Brush();
    brush.target = 0.5f;
    Steps(world, brush, 120);
    EXPECT_NEAR(world.At(16, 16), 128, 1) << "half of full weight";
    // A texel already above the target stays.
    World high;
    std::fill(high.texels.begin(), high.texels.end(), std::uint64_t{220});
    Steps(high, brush, 30);
    EXPECT_EQ(high.At(16, 16), 220);
  }

  TEST(
    MaskBrushOptions,
    TheStrokeModelDoesNotPileUp
  )
  {
    MaskBrush brush = Brush();
    brush.shape.strength = 0.5f;
    World built;
    Steps(built, brush, 120);
    EXPECT_EQ(built.At(16, 16), 255) << "build-up: a still brush keeps adding";

    brush.buildUp = false;
    World stroked;
    MaskStroke stroke;
    Steps(stroked, brush, 120, 32.0f, 32.0f, &stroke);
    EXPECT_NEAR(stroked.At(16, 16), 128, 1) << "the strongest coverage of the stroke: half way to full";

    // Erase by coverage: half of what was there before the stroke.
    World erased;
    std::fill(erased.texels.begin(), erased.texels.end(), std::uint64_t{200});
    brush.mode = MaskBrushMode::Erase;
    MaskStroke wipe;
    Steps(erased, brush, 120, 32.0f, 32.0f, &wipe);
    EXPECT_NEAR(erased.At(16, 16), 100, 1);
  }

  TEST(
    MaskBrushOptions,
    ScatterSpecklesTheSameAtEveryCopy
  )
  {
    World world;
    MaskBrush brush = Brush();
    brush.scatter = 0.8f;
    brush.scatterSeed = 7;
    brush.buildUp = false;
    brush.shape.symmetry = Symmetry::LeftRight;
    MaskStroke stroke;
    Steps(world, brush, 10, 20.0f, 32.0f, &stroke);
    int lowest = 255;
    int highest = 0;
    for (int z = 13; z <= 19; ++z) {
      for (int x = 7; x <= 12; ++x) {
        lowest = std::min(lowest, world.At(x, z));
        highest = std::max(highest, world.At(x, z));
      }
    }
    EXPECT_GT(highest - lowest, 60) << "speckled inside the brush";
    for (int z = 0; z < kMask; ++z) {
      for (int x = 0; x < kMask; ++x) {
        ASSERT_EQ(world.At(x, z), world.At(kMask - 1 - x, z)) << x << "," << z;
      }
    }
  }

  TEST(
    MaskBrushOptions,
    AMinimumSlopeLeavesFlatGroundAlone
  )
  {
    MaskBrush brush = Brush();
    brush.limitMinSlope = 0.5f;
    World flat;
    Steps(flat, brush, 60);
    EXPECT_EQ(flat.At(16, 16), 0);
    World ramp;
    for (int z = 0; z < kField; ++z) {
      for (int x = 0; x < kField; ++x) {
        ramp.heights[static_cast<std::size_t>(z * kField + x)] = static_cast<std::uint16_t>(2560 + x * 128); // 1:1
      }
    }
    Steps(ramp, brush, 60);
    EXPECT_GT(ramp.At(16, 16), 200);
  }

  TEST(
    MaskBrushOptions,
    AShapedMaskUnderSymmetryIsTheCursorsDab
  )
  {
    // The cursor on the right: each group's first texel lies by the copy on the left. The stroke model rounds without
    // build-up's dither (which is keyed to the group's first texel, so it differs from a plain stroke's by a step).
    MaskBrush brush = Brush();
    brush.shape.shape = BrushShape::Ridge;
    brush.shape.shapeAngle = 30.0f;
    brush.buildUp = false;
    World plain;
    MaskStroke plainStroke;
    Steps(plain, brush, 20, 44.0f, 30.0f, &plainStroke);
    World mirrored;
    MaskStroke mirroredStroke;
    brush.shape.symmetry = Symmetry::LeftRight;
    Steps(mirrored, brush, 20, 44.0f, 30.0f, &mirroredStroke);
    int painted = 0;
    for (int z = 8; z <= 22; ++z) {
      for (int x = 15; x <= 31; ++x) {
        ASSERT_EQ(plain.At(x, z), mirrored.At(x, z)) << x << "," << z;
        painted += plain.At(x, z) > 0 ? 1 : 0;
      }
    }
    EXPECT_GT(painted, 10);
    EXPECT_LT(painted, 120) << "a ridge, not a disc";
  }
} // namespace
