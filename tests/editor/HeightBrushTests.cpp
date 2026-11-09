// The map editor's height brush (src/editor/tools/EdHeightBrush.cpp): exact symmetry, as the plan's stage 3
// asks: every mode's copies stay bit-identical after random strokes, a stroke on a mirror line doesn't
// apply twice, and a map that isn't square falls back to no symmetry for the square-only modes.

#include "editor/tools/EdHeightBrush.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <random>
#include <vector>

namespace
{
  using faf::editor::ApplyHeightBrush;
  using faf::editor::HeightBrush;
  using faf::editor::HeightBrushMode;
  using faf::editor::SampleRect;
  using faf::editor::Symmetry;
  using faf::editor::SymmetricSamples;

  struct Field
  {
    int width;
    int height;
    std::vector<std::uint16_t> words;

    Field(const int w, const int h, const std::uint16_t fill)
      : width(w)
      , height(h)
      , words(static_cast<std::size_t>(w) * static_cast<std::size_t>(h), fill)
    {}

    [[nodiscard]] std::uint16_t At(const int x, const int z) const
    {
      return words[static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x)];
    }
  };

  /** Every sample equals each of its symmetric copies. */
  ::testing::AssertionResult CopiesEqual(const Field& field, const Symmetry symmetry)
  {
    for (int z = 0; z < field.height; ++z) {
      for (int x = 0; x < field.width; ++x) {
        int cx[faf::editor::kMaxSymmetryCopies];
        int cz[faf::editor::kMaxSymmetryCopies];
        const int n = SymmetricSamples(symmetry, 3, field.width, field.height, x, z, cx, cz);
        for (int i = 1; i < n; ++i) {
          if (field.At(cx[i], cz[i]) != field.At(x, z)) {
            return ::testing::AssertionFailure() << "(" << x << "," << z << ")=" << field.At(x, z) << " but copy (" << cx[i] << ","
                                                 << cz[i] << ")=" << field.At(cx[i], cz[i]);
          }
        }
      }
    }
    return ::testing::AssertionSuccess();
  }

  faf::editor::HeightStamp RandomStamp(const unsigned seed)
  {
    faf::editor::HeightStamp stamp;
    stamp.width = 17;
    stamp.height = 17;
    std::mt19937 random(seed * 7u + 1u);
    std::uniform_int_distribution<int> word(0, 65535);
    for (int i = 0; i < 17 * 17; ++i) {
      stamp.words.push_back(static_cast<std::uint16_t>(word(random)));
    }
    return stamp;
  }

  void RandomStrokes(Field& field, const Symmetry symmetry, const unsigned seed)
  {
    std::mt19937 random(seed);
    std::uniform_real_distribution<float> along(0.0f, static_cast<float>(field.width - 1));
    std::uniform_real_distribution<float> down(0.0f, static_cast<float>(field.height - 1));
    std::uniform_int_distribution<int> mode(0, 8);
    std::uniform_real_distribution<float> unit(0.05f, 1.0f);
    const faf::editor::HeightStamp stamp = RandomStamp(seed);
    for (int stroke = 0; stroke < 200; ++stroke) {
      HeightBrush brush;
      brush.mode = static_cast<HeightBrushMode>(mode(random));
      brush.symmetry = symmetry;
      brush.radius = 2.0f + unit(random) * 12.0f;
      brush.strength = unit(random);
      brush.falloff = unit(random);
      brush.flattenTo = unit(random) * 20000.0f;
      brush.setTo = unit(random) * 20000.0f;
      brush.terraceStep = 200.0f + unit(random) * 2000.0f;
      brush.planeSet = true;
      brush.planeX = unit(random) * 40.0 - 20.0;
      brush.planeZ = unit(random) * 40.0 - 20.0;
      brush.planeC = 8000.0;
      brush.stamp = &stamp;
      brush.limitHeight = stroke % 3 == 0;
      brush.limitLow = 6000.0f;
      brush.limitHigh = 12000.0f;
      brush.limitSlope = stroke % 5 == 0;
      brush.limitMaxSlope = 0.5f;
      (void)ApplyHeightBrush(field.words.data(), field.width, field.height, along(random), down(random), brush, 0.016f + unit(random) * 0.05f);
    }
  }

  class EverySymmetry : public ::testing::TestWithParam<Symmetry>
  {};

  TEST_P(EverySymmetry, CopiesStayIdenticalAfterRandomStrokes)
  {
    Field field(65, 65, 8000);
    RandomStrokes(field, GetParam(), 1234u + static_cast<unsigned>(GetParam()));
    EXPECT_TRUE(CopiesEqual(field, GetParam()));
  }

  INSTANTIATE_TEST_SUITE_P(
    HeightBrush, EverySymmetry,
    ::testing::Values(Symmetry::None, Symmetry::LeftRight, Symmetry::TopBottom, Symmetry::DiagonalBack, Symmetry::DiagonalForward,
                      Symmetry::HalfTurn, Symmetry::BothAxes, Symmetry::BothDiagonals, Symmetry::QuarterTurns)
  );

  /** RandomStrokes with N-way turns of `turns` copies. */
  void RandomTurnedStrokes(Field& field, const int turns, const unsigned seed)
  {
    std::mt19937 random(seed);
    std::uniform_real_distribution<float> along(0.0f, static_cast<float>(field.width - 1));
    std::uniform_int_distribution<int> mode(0, 4);
    std::uniform_real_distribution<float> unit(0.05f, 1.0f);
    for (int stroke = 0; stroke < 200; ++stroke) {
      HeightBrush brush;
      brush.mode = static_cast<HeightBrushMode>(mode(random));
      brush.symmetry = Symmetry::NWay;
      brush.turns = turns;
      brush.radius = 2.0f + unit(random) * 12.0f;
      brush.strength = unit(random);
      brush.falloff = unit(random);
      brush.flattenTo = unit(random) * 20000.0f;
      (void)ApplyHeightBrush(field.words.data(), field.width, field.height, along(random), along(random), brush, 0.016f + unit(random) * 0.05f);
    }
  }

  TEST(HeightBrush, FourWayTurnIsExact)
  {
    // Four turns land on samples: the same groups as quarter turns, bit for bit.
    Field field(65, 65, 8000);
    RandomTurnedStrokes(field, 4, 77u);
    EXPECT_TRUE(CopiesEqual(field, Symmetry::QuarterTurns));
  }

  TEST(HeightBrush, ThreeWayTurnCopiesStayClose)
  {
    // Three turns fall between samples: every painted sample stays within a small share of the raise of
    // the height at its point turned by a third, read between samples.
    Field field(129, 129, 8000);
    HeightBrush brush;
    brush.mode = HeightBrushMode::Raise;
    brush.symmetry = Symmetry::NWay;
    brush.turns = 3;
    brush.radius = 12.0f;
    brush.strength = 1.0f;
    brush.falloff = 1.0f;
    const std::vector<SampleRect> rects = ApplyHeightBrush(field.words.data(), 129, 129, 90.0f, 70.0f, brush, 0.1f);
    EXPECT_EQ(rects.size(), 3u);
    int peak = 0;
    double worst = 0.0;
    const double c = 64.0;
    for (int z = 0; z < 129; ++z) {
      for (int x = 0; x < 129; ++x) {
        peak = std::max(peak, field.At(x, z) - 8000);
        const double angle = 2.0943951023931953;
        const double px = c + (x - c) * std::cos(angle) - (z - c) * std::sin(angle);
        const double pz = c + (x - c) * std::sin(angle) + (z - c) * std::cos(angle);
        if (px < 0.0 || pz < 0.0 || px > 127.0 || pz > 127.0) {
          continue;
        }
        const int x0 = static_cast<int>(px);
        const int z0 = static_cast<int>(pz);
        const double fx = px - x0;
        const double fz = pz - z0;
        const double turned = (field.At(x0, z0) * (1.0 - fx) + field.At(x0 + 1, z0) * fx) * (1.0 - fz) +
                              (field.At(x0, z0 + 1) * (1.0 - fx) + field.At(x0 + 1, z0 + 1) * fx) * fz;
        worst = std::max(worst, std::fabs(turned - field.At(x, z)));
      }
    }
    EXPECT_GT(peak, 300);
    EXPECT_LT(worst, peak * 0.1) << "peak " << peak;
  }

  /** One step of `brush` at the middle of a 33 x 33 field of `fill`, at full strength with a hard edge. */
  Field Stepped(HeightBrush brush, const std::uint16_t fill, const float seconds = 1.0f)
  {
    Field field(33, 33, fill);
    brush.strength = 1.0f;
    brush.falloff = 0.0f;
    brush.radius = 6.0f;
    (void)ApplyHeightBrush(field.words.data(), 33, 33, 16.0f, 16.0f, brush, seconds);
    return field;
  }

  TEST(HeightBrush, SetHeightTerraceAndPlaneReachTheirTargets)
  {
    HeightBrush brush;
    brush.mode = HeightBrushMode::SetHeight;
    brush.setTo = 3000.0f;
    EXPECT_EQ(Stepped(brush, 1000).At(16, 16), 3000);
    EXPECT_EQ(Stepped(brush, 1000).At(2, 2), 1000); // outside the brush

    brush.mode = HeightBrushMode::Terrace;
    brush.terraceStep = 640.0f;
    EXPECT_EQ(Stepped(brush, 1000).At(16, 16), 1280); // 1000 is nearest the step at 1280

    double px[3] = {0.0, 32.0, 0.0};
    double ph[3] = {1000.0, 1640.0, 1320.0};
    double pz[3] = {0.0, 0.0, 32.0};
    brush.mode = HeightBrushMode::Plane;
    ASSERT_TRUE(faf::editor::PlaneThrough(px, ph, pz, brush.planeX, brush.planeZ, brush.planeC));
    brush.planeSet = true;
    EXPECT_NEAR(brush.planeX, 20.0, 1e-9);
    EXPECT_NEAR(brush.planeZ, 10.0, 1e-9);
    const Field plane = Stepped(brush, 0);
    EXPECT_EQ(plane.At(16, 16), 1000 + 20 * 16 + 10 * 16);
    EXPECT_EQ(plane.At(18, 14), 1000 + 20 * 18 + 10 * 14);
    double line[3] = {0.0, 1.0, 2.0};
    EXPECT_FALSE(faf::editor::PlaneThrough(line, ph, line, brush.planeX, brush.planeZ, brush.planeC));
  }

  TEST(HeightBrush, StampAddsItsImageTimesHeight)
  {
    faf::editor::HeightStamp stamp;
    stamp.width = 2;
    stamp.height = 2;
    stamp.words = {65535, 65535, 65535, 65535};
    HeightBrush brush;
    brush.mode = HeightBrushMode::Stamp;
    brush.stamp = &stamp;
    brush.stampHeight = 1000.0f;
    EXPECT_EQ(Stepped(brush, 500).At(16, 16), 1500);
    EXPECT_EQ(Stepped(brush, 500, 0.016f).At(16, 16), 1500); // once per click, whatever the frame's length
  }

  TEST(HeightBrush, LimitsKeepSamplesOutsideThem)
  {
    HeightBrush brush;
    brush.mode = HeightBrushMode::Raise;
    brush.limitHeight = true;
    brush.limitLow = 2000.0f;
    brush.limitHigh = 4000.0f;
    EXPECT_EQ(Stepped(brush, 1000).At(16, 16), 1000);
    EXPECT_GT(Stepped(brush, 3000).At(16, 16), 3000);

    // A ramp rising 2 units per sample: steeper than a slope limit of 1, flatter than 3.
    Field ramp(33, 33, 0);
    for (int z = 0; z < 33; ++z) {
      for (int x = 0; x < 33; ++x) {
        ramp.words[static_cast<std::size_t>(z * 33 + x)] = static_cast<std::uint16_t>(1000 + x * 256);
      }
    }
    brush = HeightBrush{};
    brush.mode = HeightBrushMode::Raise;
    brush.strength = 1.0f;
    brush.radius = 4.0f;
    brush.limitSlope = true;
    brush.limitMaxSlope = 1.0f;
    Field limited = ramp;
    (void)ApplyHeightBrush(limited.words.data(), 33, 33, 16.0f, 16.0f, brush, 0.1f);
    EXPECT_EQ(limited.words, ramp.words);
    brush.limitMaxSlope = 3.0f;
    (void)ApplyHeightBrush(limited.words.data(), 33, 33, 16.0f, 16.0f, brush, 0.1f);
    EXPECT_NE(limited.words, ramp.words);
  }

  TEST(HeightBrush, StrokeOnTheMirrorLineAppliesOnce)
  {
    // The same raise on the left-right mirror line, alone and mirrored: the copies overlap there, and each
    // sample takes the strongest copy, not their sum.
    HeightBrush brush;
    brush.mode = HeightBrushMode::Raise;
    brush.radius = 6.0f;
    brush.strength = 1.0f;
    brush.falloff = 0.5f;
    Field alone(33, 33, 1000);
    Field mirrored(33, 33, 1000);
    brush.symmetry = Symmetry::None;
    (void)ApplyHeightBrush(alone.words.data(), 33, 33, 16.0f, 16.0f, brush, 0.05f);
    brush.symmetry = Symmetry::LeftRight;
    (void)ApplyHeightBrush(mirrored.words.data(), 33, 33, 16.0f, 16.0f, brush, 0.05f);
    EXPECT_EQ(alone.words, mirrored.words);
  }

  TEST(HeightBrush, SquareOnlyModesFallBackOnARectangle)
  {
    HeightBrush brush;
    brush.symmetry = Symmetry::QuarterTurns;
    Field field(65, 33, 1000);
    const std::vector<SampleRect> rects = ApplyHeightBrush(field.words.data(), 65, 33, 10.0f, 10.0f, brush, 0.05f);
    EXPECT_EQ(rects.size(), 1u);
  }

  TEST(HeightBrush, MirroredStrokeMakesTheTouchedSamplesEqual)
  {
    // A map whose halves differ: every sample a mirrored stroke wrote equals its mirror afterwards.
    Field field(33, 33, 0);
    for (int z = 0; z < 33; ++z) {
      for (int x = 0; x < 33; ++x) {
        field.words[static_cast<std::size_t>(z * 33 + x)] = static_cast<std::uint16_t>(1000 + x * 37 + z * 11);
      }
    }
    const Field before = field;
    HeightBrush brush;
    brush.mode = HeightBrushMode::Smooth;
    brush.symmetry = Symmetry::LeftRight;
    brush.radius = 5.0f;
    brush.strength = 1.0f;
    (void)ApplyHeightBrush(field.words.data(), 33, 33, 8.0f, 12.0f, brush, 0.1f);
    int changed = 0;
    for (int z = 0; z < 33; ++z) {
      for (int x = 0; x < 33; ++x) {
        if (field.At(x, z) != before.At(x, z) || field.At(32 - x, z) != before.At(32 - x, z)) {
          ++changed;
          EXPECT_EQ(field.At(x, z), field.At(32 - x, z)) << "at (" << x << "," << z << ")";
        }
      }
    }
    EXPECT_GT(changed, 0);
  }
} // namespace
