// The fourth comparison with FAF Studio (field target): water-linked masks, the imported mask source, the reference
// maps' texture sets and recipe styles.

#include "editor/tools/EdMaskGen.h"
#include "editor/tools/EdRecipes.h"
#include "editor/tools/EdTextureSets.h"

#include <gtest/gtest.h>

#include <memory>
#include <string>

namespace
{
  using namespace faf::editor;

  constexpr int kSide = 65;

  /** A slope rising one unit a sample from x = 0 (height 0) to x = 64, the water at 20. */
  MaskGenContext Ramp()
  {
    MaskGenContext context;
    context.heights = std::make_shared<field::Grid>(kSide, kSide, 1.0f, 0.0f, 0.0f);
    for (int z = 0; z < kSide; ++z) {
      for (int x = 0; x < kSide; ++x) {
        context.heights->v[static_cast<std::size_t>(z) * kSide + x] = static_cast<float>(x);
      }
    }
    context.water = 20.0f;
    return context;
  }

  float At(
    const field::Grid& f,
    const int x
  )
  {
    return f.v[32uz * static_cast<std::size_t>(f.w) + static_cast<std::size_t>(x)];
  }

  TEST(
    RoundSixField,
    WaterLinkedMasksFollowTheWaterLevel
  )
  {
    ASSERT_EQ(std::string(WaterMaskKindName(0)), "Beach");
    ASSERT_EQ(std::string(WaterMaskKindName(4)), "Deep water");
    const auto run = [](const int kind) {
      MaskGenContext context = Ramp();
      field::Grid out;
      const auto made = EvaluateMaskRules(context, WaterMaskRules(kind, 4.0f, 6.0f, 0.5f, 60.0f), out);
      EXPECT_TRUE(made) << made.error();
      return out;
    };
    const field::Grid under = run(3);
    EXPECT_GT(At(under, 10), 0.9f);
    EXPECT_LT(At(under, 30), 0.1f);
    const field::Grid deep = run(4); // below 20 - 6
    EXPECT_GT(At(deep, 8), 0.9f);
    EXPECT_LT(At(deep, 17), 0.1f);
    const field::Grid shallows = run(2); // 14 .. 20
    EXPECT_GT(At(shallows, 17), 0.9f);
    EXPECT_LT(At(shallows, 8), 0.1f);
    EXPECT_LT(At(shallows, 26), 0.1f);
    const field::Grid beach = run(0); // 20 .. 24 above the water, the ramp is 45 degrees (gentler than 60)
    EXPECT_GT(At(beach, 22), 0.9f);
    EXPECT_LT(At(beach, 15), 0.1f);
    EXPECT_LT(At(beach, 30), 0.1f);
    // The same rules a level higher move with it.
    MaskGenContext higher = Ramp();
    higher.water = 30.0f;
    field::Grid moved;
    ASSERT_TRUE(EvaluateMaskRules(higher, WaterMaskRules(3, 4.0f, 6.0f, 0.5f, 60.0f), moved));
    EXPECT_GT(At(moved, 25), 0.9f);
  }

  TEST(
    RoundSixField,
    TheImportedMaskSourceReadsItsSlot
  )
  {
    MaskGenContext context = Ramp();
    auto imported = std::make_shared<field::Grid>(kSide, kSide, 1.0f, 0.0f, 0.0f);
    for (float& v : imported->v) {
      v = 0.75f;
    }
    context.imported[2] = imported;
    MaskGenRule rule = NewMaskRule("named");
    ASSERT_NE(MaskRuleSpecOf("named"), nullptr);
    rule.v["slot"] = 2;
    field::Grid out;
    auto made = EvaluateMaskRules(context, {rule}, out);
    ASSERT_TRUE(made) << made.error();
    EXPECT_NEAR(At(out, 10), 0.75f, 1e-4f);
    rule.v["slot"] = 3; // an empty slot masks nothing
    made = EvaluateMaskRules(context, {rule}, out);
    ASSERT_TRUE(made) << made.error();
    EXPECT_NEAR(At(out, 10), 0.0f, 1e-4f);
  }

  TEST(
    RoundSixField,
    TheReferenceMapsSetsAndStylesAreThere
  )
  {
    int sets = 0;
    for (const TextureTheme& theme : TextureThemes()) {
      sets += std::string(theme.id).starts_with("m_") ? 1 : 0;
    }
    EXPECT_EQ(sets, 35);
    int styles = 0;
    for (std::size_t i = 0; i < RecipeStyles().size(); ++i) {
      if (!std::string(RecipeStyles()[i].id).starts_with("m_")) {
        continue;
      }
      ++styles;
      EXPECT_EQ(std::string(RecipeStyles()[i].name).rfind("Environment: ", 0), 0U);
      if (std::string(RecipeStyles()[i].id) == "m_tundra") {
        EXPECT_FLOAT_EQ(RecipeKnobsOf(static_cast<int>(i)).snow, 0.45f);
        EXPECT_TRUE(RecipeStyles()[i].altForce);
      }
    }
    EXPECT_EQ(styles, 12);
  }
} // namespace
