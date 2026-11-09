// The map editor's symmetry check (src/editor/tools/EdSymmetryCheck.cpp), as the plan's stage 3 asks: it
// finds a planted one-vertex difference, and copying the source part to the copies clears it.

#include "editor/tools/EdHeightBrush.h"
#include "editor/tools/EdSymmetryCheck.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <random>
#include <vector>

namespace
{
  using faf::editor::ApplyHeightBrush;
  using faf::editor::CheckSymmetry;
  using faf::editor::HeightBrush;
  using faf::editor::HeightBrushMode;
  using faf::editor::MakeSymmetric;
  using faf::editor::Symmetry;
  using faf::editor::SymmetryReport;

  constexpr int kSize = 65;

  std::vector<std::uint16_t> Painted(const Symmetry symmetry, const int turns, const unsigned seed)
  {
    std::vector<std::uint16_t> words(static_cast<std::size_t>(kSize) * kSize, 8000);
    std::mt19937 random(seed);
    std::uniform_real_distribution<float> along(0.0f, static_cast<float>(kSize - 1));
    std::uniform_int_distribution<int> mode(0, 4);
    std::uniform_real_distribution<float> unit(0.05f, 1.0f);
    for (int stroke = 0; stroke < 100; ++stroke) {
      HeightBrush brush;
      brush.mode = static_cast<HeightBrushMode>(mode(random));
      brush.symmetry = symmetry;
      brush.turns = turns;
      brush.radius = 2.0f + unit(random) * 10.0f;
      brush.strength = unit(random);
      brush.falloff = unit(random);
      brush.flattenTo = unit(random) * 20000.0f;
      (void)ApplyHeightBrush(words.data(), kSize, kSize, along(random), along(random), brush, 0.05f);
    }
    return words;
  }

  class ExactSymmetry : public ::testing::TestWithParam<Symmetry>
  {};

  TEST_P(ExactSymmetry, FindsAPlantedVertexAndRepairsIt)
  {
    std::vector<std::uint16_t> words = Painted(GetParam(), 3, 99u);
    EXPECT_EQ(CheckSymmetry(words.data(), kSize, kSize, GetParam(), 3).differing, 0);

    // One vertex off the mirror lines raised by 3 words.
    words[static_cast<std::size_t>(9 * kSize + 5)] += 3;
    const SymmetryReport planted = CheckSymmetry(words.data(), kSize, kSize, GetParam(), 3);
    EXPECT_GE(planted.differing, 2); // the vertex and its copies all see the difference
    EXPECT_EQ(planted.largest, 3);
    bool marked = false;
    for (const faf::editor::SampleRect& block : planted.blocks) {
      marked = marked || (block.x0 <= 5 && block.x1 >= 5 && block.z0 <= 9 && block.z1 >= 9);
    }
    EXPECT_TRUE(marked);

    (void)MakeSymmetric(words.data(), kSize, kSize, GetParam(), 3);
    EXPECT_EQ(CheckSymmetry(words.data(), kSize, kSize, GetParam(), 3).differing, 0);
  }

  INSTANTIATE_TEST_SUITE_P(
    SymmetryCheck, ExactSymmetry,
    ::testing::Values(Symmetry::LeftRight, Symmetry::TopBottom, Symmetry::DiagonalBack, Symmetry::DiagonalForward, Symmetry::HalfTurn,
                      Symmetry::BothAxes, Symmetry::BothDiagonals, Symmetry::QuarterTurns)
  );

  TEST(SymmetryCheck, ThreeWayTurnPaintedByTheBrushPasses)
  {
    std::vector<std::uint16_t> words = Painted(Symmetry::NWay, 3, 5u);
    const SymmetryReport report = CheckSymmetry(words.data(), kSize, kSize, Symmetry::NWay, 3);
    EXPECT_GT(report.checked, kSize * kSize / 2);
    EXPECT_EQ(report.differing, 0) << "largest " << report.largest;
  }

  TEST(SymmetryCheck, ThreeWayTurnFindsAPlantedBump)
  {
    std::vector<std::uint16_t> words(static_cast<std::size_t>(kSize) * kSize, 8000);
    // A bump in the second sector (above the centre on the -x side) that the others don't have.
    words[static_cast<std::size_t>(50 * kSize + 20)] += 500;
    SymmetryReport report = CheckSymmetry(words.data(), kSize, kSize, Symmetry::NWay, 3);
    EXPECT_GT(report.differing, 0);
    EXPECT_GE(report.largest, 400);
    (void)MakeSymmetric(words.data(), kSize, kSize, Symmetry::NWay, 3);
    report = CheckSymmetry(words.data(), kSize, kSize, Symmetry::NWay, 3);
    EXPECT_EQ(report.differing, 0) << "largest " << report.largest;
  }

  // A field from a function of (x, z), with a little noise below the tolerance.
  template <typename F>
  std::vector<std::uint16_t> FieldOf(const int size, F f)
  {
    std::vector<std::uint16_t> field(static_cast<std::size_t>(size) * size);
    std::mt19937 random(7);
    for (int z = 0; z < size; ++z) {
      for (int x = 0; x < size; ++x) {
        field[static_cast<std::size_t>(z) * size + x] = static_cast<std::uint16_t>(f(x, z) + static_cast<int>(random() % 8));
      }
    }
    return field;
  }

  TEST(SymmetryDetect, FindsTheModeWithTheMostCopies)
  {
    constexpr int kSize = 257;
    const int last = kSize - 1;
    // Mirrored left-right only: a bump on the left and its mirror, a ridge only in the top half.
    const auto leftRight = FieldOf(kSize, [&](int x, int z) {
      const int mx = std::min(x, last - x);
      return 4000 + 20 * mx + (z < 100 ? 30 * z : 3000);
    });
    faf::editor::DetectedSymmetry found = faf::editor::DetectSymmetry(leftRight.data(), kSize, kSize);
    EXPECT_EQ(found.symmetry, Symmetry::LeftRight);
    EXPECT_GE(found.matched, 0.97f);
    // Mirrored on both axes (also left-right, top-bottom and a half turn): both axes, the most copies.
    const auto both = FieldOf(kSize, [&](int x, int z) { return 4000 + 20 * std::min(x, last - x) + 35 * std::min(z, last - z); });
    EXPECT_EQ(faf::editor::DetectSymmetry(both.data(), kSize, kSize).symmetry, Symmetry::BothAxes);
    // A half turn only.
    const auto half = FieldOf(kSize, [&](int x, int z) {
      const bool second = z > last - z || (z == last - z && x > last - x);
      const int sx = second ? last - x : x;
      const int sz = second ? last - z : z;
      return 4000 + 17 * sx + 9 * sz;
    });
    EXPECT_EQ(faf::editor::DetectSymmetry(half.data(), kSize, kSize).symmetry, Symmetry::HalfTurn);
  }

  TEST(SymmetryDetect, FlatAndRandomFieldsHaveNone)
  {
    constexpr int kSize = 129;
    const auto flat = FieldOf(kSize, [](int, int) { return 6400; });
    EXPECT_EQ(faf::editor::DetectSymmetry(flat.data(), kSize, kSize).symmetry, Symmetry::None);
    std::mt19937 random(3);
    const auto rough = FieldOf(kSize, [&](int, int) { return 4000 + static_cast<int>(random() % 4000); });
    EXPECT_EQ(faf::editor::DetectSymmetry(rough.data(), kSize, kSize).symmetry, Symmetry::None);
  }

  TEST(SymmetryCheck, NoSymmetryChecksNothing)
  {
    std::vector<std::uint16_t> words = Painted(Symmetry::None, 3, 7u);
    EXPECT_EQ(CheckSymmetry(words.data(), kSize, kSize, Symmetry::None, 3).checked, 0);
  }
} // namespace
