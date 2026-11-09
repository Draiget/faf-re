// The map editor's height brush (src/editor/tools/EdHeightBrush.cpp): exact symmetry, as the plan's stage 3
// asks: every mode's copies stay bit-identical after random strokes, a stroke on a mirror line doesn't
// apply twice, and a map that isn't square falls back to no symmetry for the square-only modes.

#include "editor/tools/EdHeightBrush.h"

#include <gtest/gtest.h>

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
        int cx[4];
        int cz[4];
        const int n = SymmetricSamples(symmetry, field.width, field.height, x, z, cx, cz);
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

  void RandomStrokes(Field& field, const Symmetry symmetry, const unsigned seed)
  {
    std::mt19937 random(seed);
    std::uniform_real_distribution<float> along(0.0f, static_cast<float>(field.width - 1));
    std::uniform_real_distribution<float> down(0.0f, static_cast<float>(field.height - 1));
    std::uniform_int_distribution<int> mode(0, 4);
    std::uniform_real_distribution<float> unit(0.05f, 1.0f);
    for (int stroke = 0; stroke < 200; ++stroke) {
      HeightBrush brush;
      brush.mode = static_cast<HeightBrushMode>(mode(random));
      brush.symmetry = symmetry;
      brush.radius = 2.0f + unit(random) * 12.0f;
      brush.strength = unit(random);
      brush.falloff = unit(random);
      brush.flattenTo = unit(random) * 20000.0f;
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
