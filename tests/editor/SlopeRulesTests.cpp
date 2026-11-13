// The sim's terrain rules behind the slope view (src/editor/tools/EdSlopeRules.h): the fast tile ratings equal the
// rules read straight, and the ring rule's pivot is ceil(the lowest ring sample) as the binary has it (0x00565179).

#include "editor/tools/EdSlopeRules.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <random>
#include <vector>

namespace
{
  namespace sr = faf::editor::sloperules;

  struct Field
  {
    int w = 0;
    int h = 0;
    std::vector<int> v;
    int operator()(
      const int x,
      const int z
    ) const
    {
      const int cx = std::clamp(x, 0, w - 1);
      const int cz = std::clamp(z, 0, h - 1);
      return v[static_cast<std::size_t>(cz) * static_cast<std::size_t>(w) + static_cast<std::size_t>(cx)];
    }
  };

  TEST(
    SlopeRules,
    TilesRateAsTheRulesDo
  )
  {
    // Rough ground: random words over a gentle ramp.
    Field f{150, 150, {}};
    f.v.resize(static_cast<std::size_t>(f.w) * f.h);
    std::mt19937 random(7);
    std::uniform_int_distribution<int> noise(0, 300);
    for (int z = 0; z < f.h; ++z) {
      for (int x = 0; x < f.w; ++x) {
        f.v[static_cast<std::size_t>(z) * f.w + x] = 4000 + x * 20 + noise(random);
      }
    }
    std::vector<std::uint16_t> tile(static_cast<std::size_t>(sr::kTile) * sr::kTile);
    for (const int kind : {sr::kKindPath, sr::kKindBuild, sr::kKindRing}) {
      for (const int n : {1, 2, 5, 8, 15}) {
        sr::RateTile(kind, n, 64, 0, f, tile.data());
        for (int j = 0; j < sr::kTile; j += 7) {
          for (int i = 0; i < sr::kTile; i += 5) {
            ASSERT_EQ(
              static_cast<int>(tile[static_cast<std::size_t>(j) * sr::kTile + i]), sr::CellRating(kind, n, 64 + i, j, f)
            ) << "kind "
              << kind << " window " << n << " cell " << i << "," << j;
          }
        }
      }
    }
  }

  TEST(
    SlopeRules,
    ThePathRuleIsTheSteepestStepInTheWindow
  )
  {
    // A ramp of half a unit (64 words) a cell along x.
    Field f{20, 20, {}};
    for (int z = 0; z < f.h; ++z) {
      for (int x = 0; x < f.w; ++x) {
        f.v.push_back(x * 64);
      }
    }
    EXPECT_EQ(sr::CellRating(sr::kKindPath, 2, 5, 5, f), 64);
    EXPECT_EQ(sr::CellRating(sr::kKindBuild, 2, 5, 5, f), 128) << "the area rule: highest minus lowest over 3 samples";
  }

  TEST(
    SlopeRulesRing,
    ThePivotIsTheCeilingOfTheLowestRingSample
  )
  {
    // A 2-cell skirt at (5, 5): the ring is x 4..8 on rows 4 and 8, and columns 4 and 8 on rows 5..7. The ring is at
    // 10.0 units (1280 words) except one sample at 1400; the last one read (8, 7) is 1350.
    Field f{14, 14, std::vector<int>(14 * 14, 1280)};
    f.v[static_cast<std::size_t>(4) * 14 + 6] = 1400;
    f.v[static_cast<std::size_t>(7) * 14 + 8] = 1350;
    // ceil(10.0) = 10: max(1400 - 1280, 1280 - 1280) = 120 words. (Pivoting on the last sample, ceil(10.55) = 11, would
    // give max(1400 - 1408, 1408 - 1280) = 128.)
    EXPECT_EQ(sr::CellRating(sr::kKindRing, 2, 5, 5, f), 120);
    EXPECT_EQ(sr::RingDeviation(1300, 1300), 1408 - 1300) << "a level ring off the whole unit still deviates";
    EXPECT_EQ(sr::CeilToUnit(1280), 1280);
    EXPECT_EQ(sr::CeilToUnit(1281), 1408);
  }

  TEST(
    SlopeRules,
    ColourStepsUpToTheLimit
  )
  {
    EXPECT_EQ(sr::ColorStep(0.0f, 0.75f), 0) << "flat: not drawn";
    EXPECT_EQ(sr::ColorStep(0.75f, 0.75f), sr::kSteps);
    EXPECT_EQ(sr::ColorStep(0.8f, 0.75f), sr::kSteps + 1) << "beyond the limit";
  }
} // namespace
