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

  TEST(HeightBrush, ErodeSlumpsAPillarWithoutMakingGround)
  {
    // A 2 x 2 pillar 2000 words (about 16 units) over flat ground at 1000, well inside the brush.
    Field field(33, 33, 1000);
    for (int z = 15; z <= 16; ++z) {
      for (int x = 15; x <= 16; ++x) {
        field.words[static_cast<std::size_t>(z) * 33 + static_cast<std::size_t>(x)] = 3000;
      }
    }
    const auto total = [&field] {
      long long sum = 0;
      for (const std::uint16_t w : field.words) {
        sum += w;
      }
      return sum;
    };
    const long long before = total();
    HeightBrush brush;
    brush.mode = HeightBrushMode::Erode;
    brush.erodeTalus = 0.6f; // 76.8 words a sample
    brush.strength = 1.0f;
    brush.falloff = 0.0f;
    brush.radius = 12.0f;
    for (int step = 0; step < 600; ++step) {
      (void)ApplyHeightBrush(field.words.data(), 33, 33, 15.5f, 15.5f, brush, 0.1f);
    }
    // The pillar has slumped into a mound...
    EXPECT_LT(field.At(15, 15), 1600);
    EXPECT_GT(field.At(15, 15), field.At(10, 15));
    // ...whose slopes are near the talus slope (a few words over, from rounding and the last steps)...
    int steepest = 0;
    for (int z = 5; z <= 26; ++z) {
      for (int x = 5; x <= 25; ++x) {
        steepest = std::max(steepest, std::abs(static_cast<int>(field.At(x + 1, z)) - static_cast<int>(field.At(x, z))));
      }
    }
    EXPECT_LT(steepest, 77 + 20);
    // ...and the ground was moved, not made: the total is the same but for rounding.
    EXPECT_NEAR(static_cast<double>(total()), static_cast<double>(before), static_cast<double>(before) * 0.0005);
  }

  TEST(HeightBrush, ErodeWorksAtTheEditorsFrameRate)
  {
    // As the editor paints: a step a frame at 60 fps, strength 0.5, for three seconds, on a ridge only a little steeper
    // than the talus (96 words a sample against 76.8). Each frame's change there is about a word; scaled like the other
    // brushes' blend it was a sixth of one, which rounded away to nothing (heights are whole words).
    Field field(33, 33, 0);
    for (int z = 0; z < 33; ++z) {
      for (int x = 0; x < 33; ++x) {
        field.words[static_cast<std::size_t>(z) * 33 + static_cast<std::size_t>(x)] = static_cast<std::uint16_t>(4000 - 96 * std::abs(x - 16));
      }
    }
    HeightBrush brush;
    brush.mode = HeightBrushMode::Erode;
    brush.erodeTalus = 0.6f;
    brush.strength = 0.5f;
    brush.radius = 8.0f;
    for (int frame = 0; frame < 180; ++frame) {
      (void)ApplyHeightBrush(field.words.data(), 33, 33, 16.0f, 16.0f, brush, 1.0f / 60.0f);
    }
    // The crest worn down towards the talus (only the crest has any excess: it settles some 10-19 words lower), its
    // slope eased. Scaled like the other brushes it stayed at 4000.
    EXPECT_LT(field.At(16, 16), 3995);
    EXPECT_LT(field.At(16, 16) - field.At(15, 16), 96);
  }

  /** A field leaning down towards +x (`drop` words a sample) with a little noise, so rain has somewhere to run. */
  Field Ramp(const int size, const int drop)
  {
    Field field(size, size, 0);
    for (int z = 0; z < size; ++z) {
      for (int x = 0; x < size; ++x) {
        const int bump = static_cast<int>((static_cast<unsigned>(x * 73856093) ^ static_cast<unsigned>(z * 19349663)) % 40u);
        field.words[static_cast<std::size_t>(z) * static_cast<std::size_t>(size) + static_cast<std::size_t>(x)] =
          static_cast<std::uint16_t>(20000 - drop * x + bump);
      }
    }
    return field;
  }

  long long TotalOf(const Field& field)
  {
    long long sum = 0;
    for (const std::uint16_t w : field.words) {
      sum += w;
    }
    return sum;
  }

  HeightBrush Rain()
  {
    HeightBrush brush;
    brush.mode = HeightBrushMode::WaterErode;
    brush.strength = 1.0f;
    brush.falloff = 0.3f;
    brush.radius = 14.0f;
    return brush;
  }

  TEST(HeightBrush, WaterErodeCarvesARampWithoutMakingGround)
  {
    Field field = Ramp(49, 60);
    const Field before = field;
    HeightBrush brush = Rain();
    for (int step = 0; step < 120; ++step) {
      brush.seed = static_cast<std::uint32_t>(step + 1);
      (void)ApplyHeightBrush(field.words.data(), 49, 49, 24.0f, 24.0f, brush, 1.0f / 60.0f);
    }
    int lowered = 0;
    int raised = 0;
    for (std::size_t i = 0; i < field.words.size(); ++i) {
      lowered += field.words[i] < before.words[i] ? 1 : 0;
      raised += field.words[i] > before.words[i] ? 1 : 0;
    }
    EXPECT_GT(lowered, 50); // channels cut...
    EXPECT_GT(raised, 20);  // ...and their ground left lower down
    // Moved, not made: the total stays within rounding (each sample rounds at random, evenly).
    EXPECT_NEAR(static_cast<double>(TotalOf(field)), static_cast<double>(TotalOf(before)), 600.0);
    // Nothing outside the brush's square changed.
    EXPECT_EQ(field.At(2, 2), before.At(2, 2));
    EXPECT_EQ(field.At(46, 46), before.At(46, 46));
  }

  TEST(HeightBrush, WaterErodeLeavesFlatGroundAndRepeatsWithItsSeed)
  {
    Field flat(33, 33, 5000);
    HeightBrush brush = Rain();
    brush.radius = 10.0f;
    for (int step = 0; step < 30; ++step) {
      brush.seed = static_cast<std::uint32_t>(step + 1);
      (void)ApplyHeightBrush(flat.words.data(), 33, 33, 16.0f, 16.0f, brush, 1.0f / 60.0f);
    }
    EXPECT_EQ(flat.words, Field(33, 33, 5000).words);

    Field a = Ramp(49, 60);
    Field b = Ramp(49, 60);
    brush = Rain();
    brush.seed = 7;
    (void)ApplyHeightBrush(a.words.data(), 49, 49, 24.0f, 24.0f, brush, 0.1f);
    (void)ApplyHeightBrush(b.words.data(), 49, 49, 24.0f, 24.0f, brush, 0.1f);
    EXPECT_EQ(a.words, b.words);
  }

  TEST(HeightBrush, WaterErodeKeepsAMirroredMapMirrored)
  {
    // Left-right mirrored hills, rained on near the mirror line and well off it.
    Field field(49, 49, 0);
    for (int z = 0; z < 49; ++z) {
      for (int x = 0; x < 49; ++x) {
        const int mx = std::min(x, 48 - x);
        field.words[static_cast<std::size_t>(z) * 49 + static_cast<std::size_t>(x)] = static_cast<std::uint16_t>(8000 + 70 * mx + 30 * z);
      }
    }
    HeightBrush brush = Rain();
    brush.symmetry = Symmetry::LeftRight;
    brush.radius = 9.0f;
    for (int step = 0; step < 60; ++step) {
      brush.seed = static_cast<std::uint32_t>(step + 1);
      (void)ApplyHeightBrush(field.words.data(), 49, 49, step % 2 == 0 ? 10.0f : 22.0f, 24.0f, brush, 1.0f / 60.0f);
    }
    EXPECT_TRUE(CopiesEqual(field, Symmetry::LeftRight));
  }

  TEST(HeightBrush, ErodeLeavesGroundGentlerThanTheTalusAlone)
  {
    Field field(33, 33, 0);
    for (int z = 0; z < 33; ++z) {
      for (int x = 0; x < 33; ++x) {
        field.words[static_cast<std::size_t>(z) * 33 + static_cast<std::size_t>(x)] = static_cast<std::uint16_t>(1000 + 40 * x); // 0.31 a unit
      }
    }
    const std::vector<std::uint16_t> before = field.words;
    HeightBrush brush;
    brush.mode = HeightBrushMode::Erode;
    brush.erodeTalus = 0.6f;
    brush.strength = 1.0f;
    brush.radius = 10.0f;
    for (int step = 0; step < 50; ++step) {
      (void)ApplyHeightBrush(field.words.data(), 33, 33, 16.0f, 16.0f, brush, 0.1f);
    }
    EXPECT_EQ(field.words, before);
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
