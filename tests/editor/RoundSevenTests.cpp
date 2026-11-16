// The fifth comparison with FAF Studio (brush target): builder calls, the unit wizard's new blueprint fields, the
// erosion brushes' settings.

#include "editor/tools/EdBuilders.h"
#include "editor/tools/EdHeightBrush.h"
#include "editor/tools/EdUnitWizard.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace
{
  using namespace faf::editor;

  TEST(
    RoundSeven,
    BuilderCallsSplitAndWriteBack
  )
  {
    const std::vector<std::string> items = LuaTableItems("{ '/lua/a.lua', 'F', { 'x', { 1, 2 } }, \"s,t\" }");
    ASSERT_EQ(items.size(), 4U);
    EXPECT_EQ(items[2], "{ 'x', { 1, 2 } }");
    EXPECT_EQ(items[3], "\"s,t\"") << "a comma inside a string stays";
    BuilderCall call;
    ASSERT_TRUE(ParseBuilderCall("{ '/lua/editor/miscbuildconditions.lua', 'True', {'default_brain'} }", call));
    EXPECT_EQ(call.file, "/lua/editor/miscbuildconditions.lua");
    EXPECT_EQ(call.function, "True");
    EXPECT_EQ(call.rest, "{'default_brain'}");
    call.function = "False";
    BuilderCall back;
    ASSERT_TRUE(ParseBuilderCall(FormatBuilderCall(call), back));
    EXPECT_EQ(back.function, "False");
    EXPECT_EQ(back.rest, "{'default_brain'}");
    EXPECT_FALSE(ParseBuilderCall("{ 1 }", back)) << "fewer than a file and a function";
    EXPECT_TRUE(LuaTableItems("not a table").empty());
  }

  TEST(
    RoundSeven,
    TheWizardWritesMotionTypeAndWhatTheUnitBuilds
  )
  {
#ifdef FAF_UNITWIZ_DATA
    std::ifstream in(FAF_UNITWIZ_DATA, std::ios::binary);
    const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UnitWizardData data;
    const auto loaded = LoadUnitWizardData(text, data);
    ASSERT_TRUE(loaded) << loaded.error();
    auto madeTank = NewUnitSpec(data, "tank", "UEF", "zel0101");
    ASSERT_TRUE(madeTank) << madeTank.error();
    UnitWizardSpec& tank = *madeTank;
    tank.motionType = "RULEUMT_Hover";
    tank.physics["MaxAcceleration"] = 3.5;
    EXPECT_NE(UnitBlueprintText(data, tank, {}, nullptr).find("RULEUMT_Hover"), std::string::npos);
    auto madeEngineer = NewUnitSpec(data, "engineer", "UEF", "zel0102");
    ASSERT_TRUE(madeEngineer) << madeEngineer.error();
    UnitWizardSpec& engineer = *madeEngineer;
    engineer.buildable = {"BUILTBYTIER1ENGINEER UEF", "BUILTBYTIER2ENGINEER UEF"};
    const std::string bp = UnitBlueprintText(data, engineer, {}, nullptr);
    EXPECT_NE(bp.find("BUILTBYTIER2ENGINEER UEF"), std::string::npos) << bp.substr(0, 400);
    // Both survive the project's spec file.
    const auto read = ReadUnitSpecs(UnitSpecsText({tank, engineer}));
    ASSERT_TRUE(read) << read.error();
    const std::vector<UnitWizardSpec>& specs = *read;
    ASSERT_EQ(specs.size(), 2U);
    EXPECT_EQ(specs[0].motionType, "RULEUMT_Hover");
    EXPECT_EQ(specs[1].buildable.size(), 2U);
#else
    GTEST_SKIP() << "no wizard data";
#endif
  }

  TEST(
    RoundSeven,
    TheDepositBrushLaysWhatItsAmountSays
  )
  {
    const auto total = [](const std::vector<std::uint16_t>& words) {
      std::uint64_t sum = 0;
      for (const std::uint16_t w : words) {
        sum += w;
      }
      return sum;
    };
    const auto run = [&](const float amount) {
      std::vector<std::uint16_t> words(41 * 41, 6000);
      HeightBrush brush;
      brush.mode = HeightBrushMode::Deposit;
      brush.strength = 1.0f;
      brush.radius = 8.0f;
      brush.ero.amount = amount;
      const ErosionStrokePtr stroke = MakeErosionStroke();
      for (int step = 0; step < 30; ++step) {
        brush.seed = static_cast<std::uint32_t>(step + 1);
        (void)ApplyHeightBrush(words.data(), 41, 41, 20.0f, 20.0f, brush, 1.0f / 60.0f, stroke.get());
      }
      return total(words) - static_cast<std::uint64_t>(41 * 41) * 6000u;
    };
    const std::uint64_t little = run(0.25f);
    const std::uint64_t much = run(2.0f);
    EXPECT_GT(little, 0U);
    EXPECT_GT(much, little * 4) << "eight times the amount lays several times the ground";
  }
} // namespace
