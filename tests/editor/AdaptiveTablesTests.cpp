// The map editor's adaptive map tables (src/editor/doc/EdAdaptiveTables.cpp): `_tables.lua` read, edited in place, written.

#include "editor/doc/EdAdaptiveTables.h"

#include <gtest/gtest.h>

namespace
{
  using faf::editor::AdaptiveTables;

  // A tables file in the template's shape: comments, per-army lines, option groups, a string entry, a table of the mapper's.
  const char* const kSample = R"lua(-- enter maximum possible player count (army slots) on the map
maxPlayerOnMap = 4

-- line number is the army's
spwnMexArmy = {     {1,2,3},
                    {4,5,6},
                    {},
                    {}}

spwnHydroArmy ={    {1},
                    {2},
                    {},
                    {}}

-- configure the amount of mexes at a certain map position
middleMexes = {{7,8},{9},{'9b'}}
extraHydros = {{}}
myOwnTable = { 'keep', 'me' } -- the mapper's own
forwardCrazyrushMexes = {10}
crazyrushOneMexes = {}
)lua";

  TEST(AdaptiveTables, EntriesAsTheScriptReadsThem)
  {
    EXPECT_EQ(faf::editor::AdaptiveEntry("Mass 07", false), "7");
    EXPECT_EQ(faf::editor::AdaptiveEntry("Mass 12", false), "12");
    EXPECT_EQ(faf::editor::AdaptiveEntry("Mass 7", false), "'7'");
    EXPECT_EQ(faf::editor::AdaptiveEntry("Mass 007", false), "'007'");
    EXPECT_EQ(faf::editor::AdaptiveEntry("Mass 9b", false), "'9b'");
    EXPECT_EQ(faf::editor::AdaptiveEntry("Hydrocarbon 03", true), "3");
    EXPECT_EQ(faf::editor::AdaptiveEntry("Hydrocarbon 03", false), "");
    EXPECT_EQ(faf::editor::AdaptiveMarkerName("7", false), "Mass 07");
    EXPECT_EQ(faf::editor::AdaptiveMarkerName("12", false), "Mass 12");
    EXPECT_EQ(faf::editor::AdaptiveMarkerName("'7'", false), "Mass 7");
    EXPECT_EQ(faf::editor::AdaptiveMarkerName("2", true), "Hydrocarbon 02");
  }

  TEST(AdaptiveTables, ReadsTheTablesTheScriptUses)
  {
    AdaptiveTables tables;
    std::string error;
    ASSERT_TRUE(faf::editor::ParseAdaptiveTables(kSample, tables, error)) << error;
    EXPECT_EQ(tables.maxPlayers, 4);
    ASSERT_EQ(tables.mexArmy.size(), 4U);
    EXPECT_EQ(tables.mexArmy[0], (std::vector<std::string>{"Mass 01", "Mass 02", "Mass 03"}));
    EXPECT_TRUE(tables.mexArmy[3].empty());
    EXPECT_EQ(tables.hydroArmy[1], (std::vector<std::string>{"Hydrocarbon 02"}));
    ASSERT_EQ(tables.options.size(), 2U);
    EXPECT_EQ(tables.options[0].first, "middleMexes");
    EXPECT_EQ(tables.options[0].second,
              (std::vector<std::vector<std::string>>{{"Mass 07", "Mass 08"}, {"Mass 09"}, {"Mass 9b"}}));
    EXPECT_EQ(tables.forwardCrazyrush, (std::vector<std::string>{"Mass 10"}));
  }

  TEST(AdaptiveTables, UnchangedTablesKeepTheFile)
  {
    AdaptiveTables tables;
    std::string error;
    ASSERT_TRUE(faf::editor::ParseAdaptiveTables(kSample, tables, error));
    // Every table the script reads is there or appended; those already there stay as written.
    const std::string out = faf::editor::WithAdaptiveTables(kSample, tables);
    EXPECT_EQ(out.substr(0, std::string(kSample).size()), kSample);
    AdaptiveTables back;
    ASSERT_TRUE(faf::editor::ParseAdaptiveTables(out, back, error)) << error;
    EXPECT_EQ(back.mexArmy, tables.mexArmy);
    EXPECT_EQ(back.forwardCrazyrush, tables.forwardCrazyrush);
  }

  TEST(AdaptiveTables, AnEditChangesOnlyItsTable)
  {
    AdaptiveTables tables;
    std::string error;
    ASSERT_TRUE(faf::editor::ParseAdaptiveTables(kSample, tables, error));
    tables.mexArmy[2] = {"Mass 11", "Mass 5"};
    const std::string out = faf::editor::WithAdaptiveTables(kSample, tables);
    EXPECT_NE(out.find("{11,'5'}"), std::string::npos);
    EXPECT_NE(out.find("-- enter maximum possible player count"), std::string::npos);
    EXPECT_NE(out.find("myOwnTable = { 'keep', 'me' } -- the mapper's own"), std::string::npos);
    EXPECT_NE(out.find("middleMexes = {{7,8},{9},{'9b'}}"), std::string::npos);
    AdaptiveTables back;
    ASSERT_TRUE(faf::editor::ParseAdaptiveTables(out, back, error)) << error;
    EXPECT_EQ(back.mexArmy, tables.mexArmy);
    EXPECT_EQ(back.hydroArmy, tables.hydroArmy);
  }

  TEST(AdaptiveTables, ANewFile)
  {
    AdaptiveTables tables;
    tables.maxPlayers = 2;
    tables.mexArmy = {{"Mass 01"}, {"Mass 02"}};
    tables.hydroArmy = {{}, {}};
    tables.options = {{"coreMexes", {{"Mass 03"}, {"Mass 04"}}}};
    const std::string out = faf::editor::WithAdaptiveTables("", tables);
    AdaptiveTables back;
    std::string error;
    ASSERT_TRUE(faf::editor::ParseAdaptiveTables(out, back, error)) << error;
    EXPECT_EQ(back.maxPlayers, 2);
    EXPECT_EQ(back.mexArmy, tables.mexArmy);
    // Every option table the script reads is written; the untouched ones as one empty group.
    EXPECT_EQ(back.options.size(), faf::editor::KnownOptionTables().size());
    for (const auto& [name, groups] : back.options) {
      if (name == "coreMexes") {
        EXPECT_EQ(groups, (std::vector<std::vector<std::string>>{{"Mass 03"}, {"Mass 04"}}));
      } else {
        EXPECT_EQ(groups, (std::vector<std::vector<std::string>>{{}}));
      }
    }
  }

  TEST(AdaptiveTables, TheScriptsImportAndTheScenarioFlag)
  {
    EXPECT_EQ(faf::editor::AdaptiveTablesPath("local Tables = import('/maps/my_map.v0003/my_map_tables.lua')\n"),
              "/maps/my_map.v0003/my_map_tables.lua");
    EXPECT_EQ(faf::editor::AdaptiveTablesPath("local ScenarioUtils = import('/lua/sim/ScenarioUtilities.lua')\n"), "");
    const std::string scenario = "version = 3\nScenarioInfo = {\n    name = 'X',\n    map_version = 3,\n}\n";
    const std::string flagged = faf::editor::WithScenarioAdaptive(scenario);
    EXPECT_EQ(flagged, "version = 3\nScenarioInfo = {\n    AdaptiveMap = true,\n    name = 'X',\n    map_version = 3,\n}\n");
    // Set where it is.
    EXPECT_EQ(faf::editor::WithScenarioAdaptive("ScenarioInfo = {\n    AdaptiveMap = false,\n}\n"), "ScenarioInfo = {\n    AdaptiveMap = true,\n}\n");
  }

  TEST(AdaptiveTables, EveryArmyHasALine)
  {
    // The script reads each absent army's line with table.getn: a line missing for any army up to maxPlayerOnMap fails.
    AdaptiveTables tables;
    tables.maxPlayers = 4;
    tables.mexArmy = {{"Mass 08"}};
    const std::string out = faf::editor::WithAdaptiveTables("", tables);
    AdaptiveTables back;
    std::string error;
    ASSERT_TRUE(faf::editor::ParseAdaptiveTables(out, back, error)) << error;
    ASSERT_EQ(back.mexArmy.size(), 4U);
    EXPECT_EQ(back.mexArmy[0], (std::vector<std::string>{"Mass 08"}));
    EXPECT_EQ(back.hydroArmy.size(), 4U);
  }

  TEST(AdaptiveTables, BrokenTextIsAnError)
  {
    AdaptiveTables tables;
    std::string error;
    EXPECT_FALSE(faf::editor::ParseAdaptiveTables("spwnMexArmy = {{1,2}", tables, error));
    EXPECT_FALSE(error.empty());
  }
} // namespace
