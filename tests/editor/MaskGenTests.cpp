// The mask generator (src/editor/tools/EdMaskGen.cpp, FAF Studio's maskgen.lua): rules on known ground, how rules
// combine, every preset, and writing a mask into a layer.

#include "editor/tools/EdMaskGen.h"

#include <gtest/gtest.h>

#include <cmath>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace
{
  using faf::editor::DescribeMaskRule;
  using faf::editor::EvaluateMaskRules;
  using faf::editor::MaskCombine;
  using faf::editor::MaskGenContext;
  using faf::editor::MaskGenRule;
  using faf::editor::MaskLayerFields;
  using faf::editor::MaskPresetRules;
  using faf::editor::MaskPresets;
  using faf::editor::MaskWriteMode;
  using faf::editor::NewMaskRule;
  using faf::editor::WriteMaskLayer;
  namespace field = faf::editor::field;

  constexpr int kSide = 65;

  /** Heights h(x, z) on a 65 x 65 grid, one unit apart. */
  template <class F>
  std::shared_ptr<field::Grid> Heights(
    F height
  )
  {
    auto grid = std::make_shared<field::Grid>(kSide, kSide, 1.0f, 0.0f, 0.0f);
    for (int z = 0; z < kSide; ++z) {
      for (int x = 0; x < kSide; ++x) {
        grid->v[static_cast<std::size_t>(z) * kSide + static_cast<std::size_t>(x)] =
          height(static_cast<float>(x), static_cast<float>(z));
      }
    }
    return grid;
  }

  float At(
    const field::Grid& f,
    const int x,
    const int z
  )
  {
    return f.v[static_cast<std::size_t>(z) * static_cast<std::size_t>(f.w) + static_cast<std::size_t>(x)];
  }

  MaskGenRule Make(
    const char* const type,
    std::initializer_list<std::pair<const char*, float>> values,
    const MaskCombine op = MaskCombine::And
  )
  {
    MaskGenRule rule = NewMaskRule(type);
    for (const auto& [key, value] : values) {
      rule.v[key] = value;
    }
    rule.op = op;
    return rule;
  }

  TEST(
    MaskGen,
    RulesStartWithTheirDefaults
  )
  {
    const MaskGenRule slope = NewMaskRule("slope");
    EXPECT_FLOAT_EQ(slope.Value("hi"), 25.0f);
    EXPECT_EQ(DescribeMaskRule(slope), "Slope  0.0 / 25.0 / 3.0");
    EXPECT_FLOAT_EQ(MaskGenRule{"height"}.Value("soft"), 4.0f) << "a missing value reads its default";
  }

  TEST(
    MaskGen,
    HeightAndSlopeBandsPickTheirGround
  )
  {
    MaskGenContext context;
    context.heights = Heights([](const float x, float) {
      return x * 0.5f; // 0..32 units, a slope of 26.6 degrees
    });
    field::Grid out;
    std::string error;
    ASSERT_TRUE(EvaluateMaskRules(context, {Make("height", {{"lo", 10}, {"hi", 20}, {"soft", 1}})}, out, error))
      << error;
    EXPECT_NEAR(At(out, 30, 32), 1.0f, 1e-4f) << "height 15";
    EXPECT_NEAR(At(out, 50, 32), 0.0f, 1e-4f) << "height 25";
    EXPECT_NEAR(At(out, 4, 32), 0.0f, 1e-4f) << "height 2";
    ASSERT_TRUE(EvaluateMaskRules(context, {Make("slope", {{"lo", 20}, {"hi", 35}, {"soft", 1}})}, out, error))
      << error;
    EXPECT_NEAR(At(out, 32, 32), 1.0f, 1e-3f) << "26.6 degrees is in 20..35";
    ASSERT_TRUE(EvaluateMaskRules(context, {Make("slope", {{"lo", 0}, {"hi", 15}, {"soft", 1}})}, out, error)) << error;
    EXPECT_NEAR(At(out, 32, 32), 0.0f, 1e-3f);
  }

  TEST(
    MaskGen,
    RulesCombineAndModifiersChangeTheResult
  )
  {
    MaskGenContext context;
    context.heights = Heights([](const float x, float) {
      return x * 0.5f;
    });
    const MaskGenRule low = Make("height", {{"lo", -10}, {"hi", 12}, {"soft", 1}});  // x below 24
    const MaskGenRule middle = Make("height", {{"lo", 8}, {"hi", 20}, {"soft", 1}}); // x 16..40
    field::Grid out;
    std::string error;
    MaskGenRule both = middle;
    both.op = MaskCombine::And;
    ASSERT_TRUE(EvaluateMaskRules(context, {low, both}, out, error)) << error;
    EXPECT_NEAR(At(out, 20, 5), 1.0f, 1e-4f) << "in both";
    EXPECT_NEAR(At(out, 30, 5), 0.0f, 1e-4f) << "only in the middle band";
    MaskGenRule either = middle;
    either.op = MaskCombine::Or;
    ASSERT_TRUE(EvaluateMaskRules(context, {low, either}, out, error)) << error;
    EXPECT_NEAR(At(out, 30, 5), 1.0f, 1e-4f);
    EXPECT_NEAR(At(out, 60, 5), 0.0f, 1e-4f);
    MaskGenRule minus = middle;
    minus.op = MaskCombine::Sub;
    ASSERT_TRUE(EvaluateMaskRules(context, {low, minus}, out, error)) << error;
    EXPECT_NEAR(At(out, 4, 5), 1.0f, 1e-4f) << "low, not in the middle band";
    EXPECT_NEAR(At(out, 20, 5), 0.0f, 1e-4f) << "taken away";
    MaskGenRule inverted = low;
    inverted.invert = true;
    ASSERT_TRUE(EvaluateMaskRules(context, {inverted}, out, error)) << error;
    EXPECT_NEAR(At(out, 60, 5), 1.0f, 1e-4f);
    ASSERT_TRUE(EvaluateMaskRules(context, {low, NewMaskRule("not")}, out, error)) << error;
    EXPECT_NEAR(At(out, 4, 5), 0.0f, 1e-4f) << "Not inverts the result so far";
    MaskGenRule off = low;
    off.enabled = false;
    EXPECT_FALSE(EvaluateMaskRules(context, {off}, out, error)) << "nothing switched on";
  }

  TEST(
    MaskGen,
    EveryPresetRuns
  )
  {
    MaskGenContext context;
    // Hills over a sea at 20: water, shore, steep and flat ground, ridges and gullies.
    context.heights = Heights([](const float x, const float z) {
      return 20.0f + 18.0f * std::sin(x * 0.15f) * std::cos(z * 0.12f) + 0.3f * x;
    });
    context.water = 20.0f;
    for (const auto& preset : MaskPresets()) {
      field::Grid out;
      std::string error;
      const std::vector<MaskGenRule> rules = MaskPresetRules(preset.id, 0.0f, 60.0f);
      ASSERT_FALSE(rules.empty()) << preset.id;
      ASSERT_TRUE(EvaluateMaskRules(context, rules, out, error)) << preset.id << ": " << error;
      ASSERT_EQ(out.v.size(), static_cast<std::size_t>(kSide) * kSide) << preset.id;
      for (const float v : out.v) {
        ASSERT_TRUE(v >= -1e-4f && v <= 1.0f + 1e-4f) << preset.id << " gave " << v;
      }
    }
    EXPECT_TRUE(MaskPresetRules("no such preset", 0, 1).empty());
  }

  TEST(
    MaskGen,
    WritingAMaskIntoALayer
  )
  {
    // A 4 x 1 mask grid over a 64-unit map; the mask is 1 on the left half.
    field::Grid mask(kSide, kSide, 1.0f, 0.0f, 0.0f);
    for (int z = 0; z < kSide; ++z) {
      for (int x = 0; x < kSide; ++x) {
        mask.v[static_cast<std::size_t>(z) * kSide + static_cast<std::size_t>(x)] = x < 32 ? 1.0f : 0.0f;
      }
    }
    std::vector<std::uint64_t> texels(4, 0);
    texels[3] = std::uint64_t{200} << 8; // layer 2 at 200 on the far right
    std::size_t changed = WriteMaskLayer(texels.data(), 4, 1, 64.0f, 2, 0, mask, MaskWriteMode::Replace, 1.0f, false);
    EXPECT_EQ(changed, 3U);
    EXPECT_EQ((texels[0] >> 8) & 0xFF, 255U);
    EXPECT_EQ((texels[3] >> 8) & 0xFF, 0U) << "replaced";
    texels[3] = std::uint64_t{200} << 8;
    (void)WriteMaskLayer(texels.data(), 4, 1, 64.0f, 2, 0, mask, MaskWriteMode::AddTo, 1.0f, false);
    EXPECT_EQ((texels[3] >> 8) & 0xFF, 200U) << "add to keeps the larger";
    (void)WriteMaskLayer(texels.data(), 4, 1, 64.0f, 2, 0, mask, MaskWriteMode::SubtractFrom, 1.0f, false);
    EXPECT_EQ((texels[0] >> 8) & 0xFF, 0U) << "subtracted";
    // Half strength in the half range: weight 0.5 is stored as (127.5 + 255) / 2.
    std::vector<std::uint64_t> half(4, 0);
    (void)WriteMaskLayer(half.data(), 4, 1, 64.0f, 1, 0xFF, mask, MaskWriteMode::Replace, 0.5f, false);
    EXPECT_NEAR(static_cast<int>(half[0] & 0xFF), 191, 1);
    // Kept to what the layers above leave free: layer 3 full on texel 0.
    std::vector<std::uint64_t> covered(4, 0);
    covered[0] = std::uint64_t{255} << 16;
    (void)WriteMaskLayer(covered.data(), 4, 1, 64.0f, 2, 0, mask, MaskWriteMode::Replace, 1.0f, true);
    EXPECT_EQ((covered[0] >> 8) & 0xFF, 0U) << "layer 3 covers it";
    EXPECT_EQ((covered[1] >> 8) & 0xFF, 255U);
  }

  TEST(
    MaskGen,
    LayerRulesReadThePaint
  )
  {
    MaskGenContext context;
    context.heights = Heights([](float, float) {
      return 10.0f;
    });
    // A 2 x 2 mask grid over the 64-unit map: layer 1 full on the left, layer 2 full at the bottom right.
    const std::uint64_t texels[4] = {0xFF, 0, 0xFF, std::uint64_t{0xFF} << 8};
    MaskLayerFields(texels, 2, 2, 64.0f, 0, context);
    field::Grid out;
    std::string error;
    ASSERT_TRUE(EvaluateMaskRules(context, {Make("layer", {{"layer", 1}})}, out, error)) << error;
    EXPECT_NEAR(At(out, 8, 8), 1.0f, 1e-3f);
    EXPECT_NEAR(At(out, 56, 8), 0.0f, 1e-3f);
    ASSERT_TRUE(EvaluateMaskRules(context, {Make("free_above", {{"layer", 1}})}, out, error)) << error;
    EXPECT_NEAR(At(out, 56, 56), 0.0f, 1e-3f) << "layer 2 covers the bottom right";
    EXPECT_NEAR(At(out, 56, 8), 1.0f, 1e-3f);
  }
} // namespace
