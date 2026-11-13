// Stratum recipes (src/editor/tools/EdRecipes.cpp, FAF Studio's recipes.lua): the map's numbers, the plan of which
// layer holds which kind, and a whole recipe on a made-up island.

#include "editor/tools/EdRecipes.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>
#include <memory>
#include <numeric>
#include <vector>

namespace
{
  using namespace faf::editor;
  namespace field = faf::editor::field;

  TEST(
    Recipes,
    PercentilesAndLandStats
  )
  {
    std::vector<float> values(1001);
    for (std::size_t i = 0; i < values.size(); ++i) {
      values[i] = static_cast<float>(i) * 0.1f; // 0..100
    }
    std::array<float, 101> pct{};
    ASSERT_TRUE(RecipePercentiles(values, pct));
    EXPECT_FLOAT_EQ(pct[0], 0.0f);
    EXPECT_FLOAT_EQ(pct[100], 100.0f);
    EXPECT_NEAR(pct[50], 50.0f, 0.3f);
    // With the sea at 50: the land is the upper half, its median 75.
    const RecipeStats st = RecipeStatsOf(values, 50.0f, true);
    EXPECT_TRUE(st.hasWater);
    EXPECT_NEAR(RecipeHeightAt(st, 0.5f), 75.0f, 0.3f);
    EXPECT_FALSE(RecipeStatsOf(values, 50.0f, false).hasWater) << "water off";
  }

  TEST(
    Recipes,
    ThePlanFollowsTheTexturesNotTheNumbers
  )
  {
    std::array<GroundKind, 9> kinds{};
    std::array<bool, 9> textured{};
    kinds[0] = GroundKind::Sand;
    kinds[2] = GroundKind::Rock;
    kinds[3] = GroundKind::Grass;
    kinds[5] = GroundKind::Grass;
    kinds[8] = GroundKind::Snow;
    for (const int l : {0, 1, 2, 3, 5, 8}) {
      textured[static_cast<std::size_t>(l)] = true;
    }
    const RecipePlan plan = PlanRecipe(kinds, textured, 7, false);
    EXPECT_EQ(plan.base, GroundKind::Sand);
    EXPECT_EQ(plan.byKind[static_cast<std::size_t>(GroundKind::Grass)], (std::vector<int>{3, 5}));
    EXPECT_EQ(plan.unknown, std::vector<int>{1}) << "a texture of no known kind";
    EXPECT_EQ(plan.beyond, std::vector<int>{8}) << "the shader paints 7 layers";
    EXPECT_FALSE(plan.Has(GroundKind::Snow));
  }

  /** An island: the sea at 20, a beach rising gently, a steep hill and a peak at about 90. */
  std::shared_ptr<field::Grid> Island(
    const int side
  )
  {
    auto grid = std::make_shared<field::Grid>(side, side, 1.0f, 0.0f, 0.0f);
    const float c = static_cast<float>(side - 1) * 0.5f;
    for (int z = 0; z < side; ++z) {
      for (int x = 0; x < side; ++x) {
        const float r = std::hypot(static_cast<float>(x) - c, static_cast<float>(z) - c) / c; // 0 middle, 1 edge
        // Gentle from the shore, steep around r 0.35, a cap above it.
        const float gentle = 20.0f + 18.0f * (1.0f - r);
        const float steep = 55.0f * std::clamp((0.42f - r) / 0.1f, 0.0f, 1.0f);
        grid->v[static_cast<std::size_t>(z) * side + static_cast<std::size_t>(x)] = gentle + steep - 4.0f;
      }
    }
    return grid;
  }

  TEST(
    Recipes,
    AnIslandGetsBeachRockAndSnowWhereTheyBelong
  )
  {
    constexpr int kSide = 129;
    MaskGenContext context;
    context.heights = Island(kSide);
    context.water = 20.0f;
    std::array<GroundKind, 9> kinds{};
    std::array<bool, 9> textured{};
    kinds[0] = GroundKind::Grass;
    kinds[1] = GroundKind::Sand;
    kinds[2] = GroundKind::Rock;
    kinds[3] = GroundKind::Snow;
    for (const int l : {0, 1, 2, 3}) {
      textured[static_cast<std::size_t>(l)] = true;
    }
    const RecipePlan plan = PlanRecipe(kinds, textured, 8, false);
    const RecipeStats st = RecipeStatsOf(context.heights->v, 20.0f, true);
    const int style = 1; // alpine: altitude always counts
    const RecipeKnobs knobs = RecipeKnobsOf(style);
    std::vector<RecipeRole> roles;
    std::string error;
    ASSERT_TRUE(RecipeRoles(context, plan, st, knobs, style, roles, error)) << error;
    std::map<int, field::Grid> target;
    ASSERT_TRUE(ResolveRecipe(context, plan, roles, knobs, target, error)) << error;
    ASSERT_EQ(target.count(1) + target.count(2) + target.count(3), 3U);
    // The weights where they belong: sand on the shore, rock on the steep ring, snow on the top.
    const float c = (kSide - 1) * 0.5f;
    const auto at = [&](const int layer, const float r) {
      return SampleField(target[layer], c + r * c, c);
    };
    EXPECT_GT(at(1, 0.93f), 0.3f) << "sand on the beach";
    EXPECT_LT(at(1, 0.15f), 0.05f) << "no sand on the top";
    EXPECT_GT(at(2, 0.37f), 0.3f) << "rock on the steep ring";
    EXPECT_GT(at(3, 0.05f), 0.3f) << "snow on the top";
    EXPECT_LT(at(3, 0.8f), 0.05f) << "no snow low down";

    // Written into empty masks over a 128-unit map: the shares add up to one.
    constexpr int kMask = 64;
    std::vector<std::uint64_t> texels(static_cast<std::size_t>(kMask) * kMask, 0);
    std::array<float, 9> shares{};
    const std::size_t changed = WriteRecipe(texels.data(), kMask, kMask, 128.0f, 0, 8, textured, target, shares);
    EXPECT_GT(changed, 0U);
    EXPECT_NEAR(std::accumulate(shares.begin(), shares.end(), 0.0f), 1.0f, 1e-3f);
    EXPECT_GT(shares[0], shares[3]) << "grass, the base, shows more than the snow cap";
  }

  TEST(
    Recipes,
    AStyleWithoutAKindClearsItsLayer
  )
  {
    constexpr int kSide = 65;
    MaskGenContext context;
    context.heights = Island(kSide);
    context.water = 20.0f;
    std::array<GroundKind, 9> kinds{};
    std::array<bool, 9> textured{};
    kinds[0] = GroundKind::Grass;
    kinds[1] = GroundKind::Snow;
    textured[0] = textured[1] = true;
    const RecipePlan plan = PlanRecipe(kinds, textured, 8, false);
    const RecipeStats st = RecipeStatsOf(context.heights->v, 20.0f, true);
    const int desert = 2;
    std::vector<RecipeRole> roles;
    std::string error;
    ASSERT_TRUE(RecipeRoles(context, plan, st, RecipeKnobsOf(desert), desert, roles, error)) << error;
    std::map<int, field::Grid> target;
    ASSERT_TRUE(ResolveRecipe(context, plan, roles, RecipeKnobsOf(desert), target, error)) << error;
    std::vector<std::uint64_t> texels(16, 0xFF); // layer 1 (snow) painted everywhere
    std::array<float, 9> shares{};
    (void)WriteRecipe(texels.data(), 4, 4, 64.0f, 0, 8, textured, target, shares);
    EXPECT_EQ(texels[5] & 0xFF, 0U) << "the desert has no snow: its layer is cleared";
    EXPECT_NEAR(shares[0], 1.0f, 1e-4f);
  }
} // namespace
