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

  // An `_options.lua` in the shape FAF's adaptive maps have: a comment, an option with a brace in its help, ours after it.
  const char* const kOptions = R"lua(options ={

{
	default = 1,
	label = "Audio lines",
	help = "Audio lines {disabled}/enabled.",
	key = 'optional_replicas',
	pref = 'optional_replicas',
	values = {
		{ text = "disabled", help = "No Audio lines.", key = 1, },
		{ text = "enabled", help = "Yes Audio lines.", key = 2, },
	},
},
-- key = 'middle_mexes' in a comment is not the option
{
    default = 2,
    label = "Middle Mexes",
    help = "Configure the amount of mexes at the middle of the map.",
    key = 'middle_mexes',
    pref = 'middle_mexes',
    values = {
        { text = "disabled", help = "No additional mexes in the middle.", key = 1, },
        { text = "enabled", help = "Spawn 4 mexes in the middle.", key = 2, },
    },
},

}
)lua";

  TEST(AdaptiveTables, OptionKeyIsTheTablesNameInSnakeCase)
  {
    EXPECT_EQ(faf::editor::AdaptiveOptionKey("middleMexes"), "middle_mexes");
    EXPECT_EQ(faf::editor::AdaptiveOptionKey("extraBaseMexes"), "extra_base_mexes");
    EXPECT_EQ(faf::editor::AdaptiveOptionKey("extraHydros"), "extra_hydros");
  }

  TEST(AdaptiveTables, FindsALobbyOptionAndItsValues)
  {
    const faf::editor::LobbyOption middle = faf::editor::FindLobbyOption(kOptions, "middle_mexes");
    EXPECT_TRUE(middle.found);
    EXPECT_EQ(middle.values, 2);
    EXPECT_EQ(middle.defaultKey, 2);
    EXPECT_FALSE(faf::editor::FindLobbyOption(kOptions, "side_mexes").found);
    // A value's own `key = 1` is not an option.
    EXPECT_FALSE(faf::editor::FindLobbyOption(kOptions, "1").found);
  }

  TEST(AdaptiveTables, RewritesALobbyOptionWhereItIs)
  {
    const std::string out = faf::editor::WithLobbyOption(kOptions, "middle_mexes", "Middle mexes", false, {2, 3});
    const faf::editor::LobbyOption middle = faf::editor::FindLobbyOption(out, "middle_mexes");
    EXPECT_TRUE(middle.found);
    EXPECT_EQ(middle.values, 3); // none, group 1, groups 1-2
    EXPECT_EQ(middle.defaultKey, 2); // kept: still one of the values
    EXPECT_NE(out.find("Groups 1 to 2 spawn (5 mexes)"), std::string::npos);
    // The other option and the comment are kept, and the option isn't written twice.
    EXPECT_NE(out.find("Audio lines {disabled}/enabled."), std::string::npos);
    EXPECT_NE(out.find("-- key = 'middle_mexes' in a comment"), std::string::npos);
    EXPECT_EQ(out.find("key = 'middle_mexes'", out.find("key = 'middle_mexes',") + 1), std::string::npos);
  }

  TEST(AdaptiveTables, AddsALobbyOptionAtTheEnd)
  {
    const std::string out = faf::editor::WithLobbyOption(kOptions, "side_mexes", "Side mexes", false, {4});
    const faf::editor::LobbyOption side = faf::editor::FindLobbyOption(out, "side_mexes");
    EXPECT_TRUE(side.found);
    EXPECT_EQ(side.values, 2);
    EXPECT_EQ(side.defaultKey, 1);
    EXPECT_GT(out.find("key = 'side_mexes'"), out.find("key = 'middle_mexes'"));
    EXPECT_TRUE(faf::editor::FindLobbyOption(out, "middle_mexes").found);
    EXPECT_TRUE(faf::editor::FindLobbyOption(out, "optional_replicas").found);
  }

  TEST(AdaptiveTables, RemovesALobbyOption)
  {
    const std::string out = faf::editor::WithoutLobbyOption(kOptions, "middle_mexes");
    EXPECT_FALSE(faf::editor::FindLobbyOption(out, "middle_mexes").found);
    EXPECT_TRUE(faf::editor::FindLobbyOption(out, "optional_replicas").found);
    EXPECT_EQ(faf::editor::WithoutLobbyOption(kOptions, "side_mexes"), kOptions);
    // Taken out and written again, it reads as before.
    const std::string again = faf::editor::WithLobbyOption(out, "middle_mexes", "Middle mexes", false, {4});
    EXPECT_EQ(faf::editor::FindLobbyOption(again, "middle_mexes").values, 2);
  }

  TEST(AdaptiveTables, MakesAnOptionsFileWhenThereIsNone)
  {
    const std::string out = faf::editor::WithLobbyOption("", "extra_hydros", "Extra hydrocarbons", true, {1, 1});
    EXPECT_EQ(out.rfind("options = {", 0), 0U);
    const faf::editor::LobbyOption hydros = faf::editor::FindLobbyOption(out, "extra_hydros");
    EXPECT_TRUE(hydros.found);
    EXPECT_EQ(hydros.values, 3);
    EXPECT_NE(out.find("(2 hydrocarbons)"), std::string::npos);
  }
} // namespace
