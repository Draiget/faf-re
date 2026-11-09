// The map editor's _save.lua model (src/editor/doc/EdSaveFile.cpp): markers and areas parsed out of the
// game's layout, the text written back unchanged when nothing changed, and only the changed block rewritten
// otherwise; the script's playable area found, set and removed.

#include "editor/doc/EdSaveFile.h"

#include <gtest/gtest.h>

#include <string>

namespace
{
  using faf::editor::SaveFile;

  const char* const kSave = R"(--[[                                                                           ]]--
--[[  Automatically generated code (do not edit)                               ]]--
Scenario = {
    next_area_id = '1',
    Props = {
    },
    --[[  Areas  ]]--
    Areas = {
        ['AREA_1'] = {
            ['rectangle'] = RECTANGLE( 0, 0, 512, 512 ),
        },
    },
    MasterChain = {
        ['_MASTERCHAIN_'] = {
            Markers = {
                ['ARMY_1'] = {
                    ['color'] = STRING( 'ff800080' ),
                    ['type'] = STRING( 'Blank Marker' ),
                    ['orientation'] = VECTOR3( 0, 0.000602126, 0 ),
                    ['position'] = VECTOR3( 672.5, 18.6797, 346.5 ),
                },
                ['Mass 01'] = {
                    ['size'] = FLOAT( 1.000000 ),
                    ['resource'] = BOOLEAN( true ),
                    ['amount'] = FLOAT( 100.000000 ),
                    ['color'] = STRING( 'ff808080' ),
                    ['editorIcon'] = STRING( '/textures/editor/marker_mass.bmp' ),
                    ['type'] = STRING( 'Mass' ),
                    ['prop'] = STRING( '/env/common/props/markers/M_Mass_prop.bp' ),
                    ['orientation'] = VECTOR3( 0, -0, 0 ),
                    ['position'] = VECTOR3( 100.5, 20, 200.5 ),
                },
            },
        },
    },
    Chains = {
        ['Naval_Chain_Left'] = {
            Markers = {
                "Naval Link 00",
            },
        },
    },
    Armies =
    {
        --[[  Army  ]]--
        ['ARMY_1'] =
        {
            personality = '',
            plans = '',
            color = 0,
            faction = 0,
            Economy = {
                mass = 0,
                energy = 0,
            },
            Alliances = {
            },
            ['Units'] = GROUP {
                orders = '',
                platoon = '',
                Units = {
                },
            },
            PlatoonBuilders = {
                next_platoon_builder_id = '0',
                Builders = {
                },
            },
        },
    },
}
)";

  TEST(SaveFile, ParsesMarkersAndAreasAndWritesBackUnchanged)
  {
    SaveFile save;
    std::string error;
    ASSERT_TRUE(save.Parse(kSave, error)) << error;
    ASSERT_EQ(save.Markers().size(), 2u);
    EXPECT_EQ(save.Markers()[1].name, "Mass 01");
    EXPECT_EQ(faf::editor::ValueString(save.Markers()[1].Get("type")), "Mass");
    const std::vector<double> position = faf::editor::ValueNumbers(save.Markers()[0].Get("position"));
    ASSERT_EQ(position.size(), 3u);
    EXPECT_DOUBLE_EQ(position[0], 672.5);
    ASSERT_EQ(save.Areas().size(), 1u);
    EXPECT_EQ(faf::editor::ValueNumbers(save.Areas()[0].Get("rectangle")).size(), 4u);
    EXPECT_FALSE(save.Changed());
    EXPECT_EQ(save.Text(), kSave);
  }

  TEST(SaveFile, AChangedBlockIsRewrittenAndReadsBack)
  {
    SaveFile save;
    std::string error;
    ASSERT_TRUE(save.Parse(kSave, error)) << error;
    save.Markers()[1].Set("position", faf::editor::Vector3Value(300.5, 22.25, 400.5));
    faf::editor::SaveEntry hydro;
    hydro.name = "Hydrocarbon 00";
    hydro.Set("type", faf::editor::StringValue("Hydrocarbon"));
    hydro.Set("position", faf::editor::Vector3Value(10, 20, 30));
    save.Markers().push_back(hydro);
    EXPECT_TRUE(save.Changed());
    const std::string text = save.Text();
    // The rest of the file is as it was.
    EXPECT_NE(text.find("['rectangle'] = RECTANGLE( 0, 0, 512, 512 ),"), std::string::npos);
    EXPECT_NE(text.find("\"Naval Link 00\","), std::string::npos);
    SaveFile again;
    ASSERT_TRUE(again.Parse(text, error)) << error;
    ASSERT_EQ(again.Markers().size(), 3u);
    EXPECT_EQ(again.Markers()[0], save.Markers()[0]);
    EXPECT_EQ(faf::editor::ValueNumbers(again.Markers()[1].Get("position"))[0], 300.5);
    EXPECT_EQ(again.Markers()[2].name, "Hydrocarbon 00");
    EXPECT_EQ(again.Areas(), save.Areas());
  }

  TEST(SaveFile, AreasAreChangedAlone)
  {
    SaveFile save;
    std::string error;
    ASSERT_TRUE(save.Parse(kSave, error)) << error;
    save.Areas()[0].Set("rectangle", faf::editor::RectangleValue(16, 32, 496, 480));
    const std::string text = save.Text();
    EXPECT_NE(text.find("RECTANGLE( 16, 32, 496, 480 )"), std::string::npos);
    EXPECT_NE(text.find("['position'] = VECTOR3( 672.5, 18.6797, 346.5 ),"), std::string::npos);
    SaveFile again;
    ASSERT_TRUE(again.Parse(text, error)) << error;
    EXPECT_EQ(again.Markers(), save.Markers());
  }

  TEST(SaveFile, ArmiesAreParsedAndAdded)
  {
    SaveFile save;
    std::string error;
    ASSERT_TRUE(save.Parse(kSave, error)) << error;
    ASSERT_EQ(save.Armies().size(), 1u);
    EXPECT_EQ(save.Armies()[0].name, "ARMY_1");
    EXPECT_EQ(save.Armies()[0].Get("plans"), "''");
    EXPECT_EQ(save.Text(), kSave);
    save.Armies().push_back(faf::editor::NewArmyEntry("ARMY_2"));
    SaveFile again;
    ASSERT_TRUE(again.Parse(save.Text(), error)) << error;
    ASSERT_EQ(again.Armies().size(), 2u);
    EXPECT_EQ(again.Armies()[1].name, "ARMY_2");
    EXPECT_EQ(again.Markers(), save.Markers());
  }

  TEST(SaveFile, ScenarioArmiesAreReadAndWritten)
  {
    const std::string scenario = "Configurations = {\n ['standard'] = {\n teams = {\n { name = 'FFA', armies = {'ARMY_1','ARMY_2',} },\n },\n"
                                 " customprops = {\n ['ExtraArmies'] = STRING( 'ARMY_9 NEUTRAL_CIVILIAN' ),\n },\n },\n}\n";
    const std::vector<std::string> armies = faf::editor::ScenarioArmies(scenario);
    ASSERT_EQ(armies.size(), 2u);
    EXPECT_EQ(armies[1], "ARMY_2");
    const std::string more = faf::editor::WithScenarioArmies(scenario, {"ARMY_1", "ARMY_2", "ARMY_3"});
    EXPECT_EQ(faf::editor::ScenarioArmies(more).size(), 3u);
    EXPECT_NE(more.find("name = 'FFA'"), std::string::npos);
    const std::vector<std::string> extra = faf::editor::ScenarioExtraArmies(scenario);
    ASSERT_EQ(extra.size(), 2u);
    EXPECT_EQ(extra[1], "NEUTRAL_CIVILIAN");
    const std::string fewer = faf::editor::WithScenarioExtraArmies(more, {"NEUTRAL_CIVILIAN"});
    ASSERT_EQ(faf::editor::ScenarioExtraArmies(fewer).size(), 1u);
    EXPECT_EQ(faf::editor::ScenarioArmies(fewer).size(), 3u);
  }

  TEST(SaveFile, AChangedEntryKeepsTheRestAsItWas)
  {
    // CR LF line ends, a banner between the entries, bare keys: what the game's saves look like.
    const std::string text = "Scenario = {\r\n    MasterChain = {\r\n        ['_MASTERCHAIN_'] = {\r\n            Markers = {\r\n"
                             "                --[[ the first ]]--\r\n"
                             "                ['A'] = {\r\n                    ['type'] = STRING( 'Mass' ),\r\n"
                             "                    ['position'] = VECTOR3( 1, 2, 3 ),\r\n                },\r\n"
                             "                --[[ the second ]]--\r\n"
                             "                ['B'] = {\r\n                    ['type'] = STRING( 'Mass' ),\r\n"
                             "                    ['position'] = VECTOR3( 4, 5, 6 ),\r\n                },\r\n"
                             "            },\r\n        },\r\n    },\r\n}\r\n";
    SaveFile save;
    std::string error;
    ASSERT_TRUE(save.Parse(text, error)) << error;
    ASSERT_EQ(save.Markers().size(), 2u);
    // B moves: only its position's text changes.
    save.Markers()[1].Set("position", "VECTOR3( 7, 8, 9 )");
    std::string expected = text;
    expected.replace(expected.find("VECTOR3( 4, 5, 6 )"), std::string("VECTOR3( 4, 5, 6 )").size(), "VECTOR3( 7, 8, 9 )");
    EXPECT_EQ(save.Text(), expected);
    // A new marker comes at the end in the file's line ends; A and the banners stay.
    faf::editor::SaveEntry c{"C", {{"type", "STRING( 'Mass' )"}, {"position", "VECTOR3( 0, 0, 0 )"}}};
    save.Markers().push_back(c);
    const std::string more = save.Text();
    EXPECT_NE(more.find("--[[ the second ]]--"), std::string::npos);
    EXPECT_NE(more.find("['C'] = {\r\n"), std::string::npos);
    EXPECT_EQ(more.find("\n") , more.find("\r\n") + 1);
    std::size_t bare = 0;
    for (std::size_t i = 0; i < more.size(); ++i) {
      bare += more[i] == '\n' && (i == 0 || more[i - 1] != '\r') ? 1 : 0;
    }
    EXPECT_EQ(bare, 0u);
    // A deleted marker takes its banner with it.
    save.Markers().erase(save.Markers().begin());
    const std::string fewer = save.Text();
    EXPECT_EQ(fewer.find("--[[ the first ]]--"), std::string::npos);
    EXPECT_NE(fewer.find("['B']"), std::string::npos);
  }

  TEST(SaveFile, ScenarioTeamsAreReadAndWritten)
  {
    // As the game's scenarios write them (SCMP_009): one team on one line.
    const std::string scenario = "version = 3\nScenarioInfo = {\n    Configurations = {\n        ['standard'] = {\n            teams = {\n"
                                 "                { name = 'FFA', armies = {'ARMY_1','ARMY_2','ARMY_3',} },\n            },\n"
                                 "            customprops = {\n                ['ExtraArmies'] = STRING( 'ARMY_9 NEUTRAL_CIVILIAN' ),\n"
                                 "            },\n        },\n    },\n}\n";
    std::vector<faf::editor::ScenarioTeam> teams = faf::editor::ScenarioTeams(scenario);
    ASSERT_EQ(teams.size(), 1u);
    EXPECT_EQ(teams[0].name, "FFA");
    ASSERT_EQ(teams[0].armies.size(), 3u);
    // Unchanged teams write the same text back.
    EXPECT_EQ(faf::editor::WithScenarioTeams(scenario, teams), scenario);
    // Two teams: ARMY_3 moves to a new one.
    teams[0].armies.pop_back();
    teams.push_back({"Bottom", {"ARMY_3"}});
    const std::string two = faf::editor::WithScenarioTeams(scenario, teams);
    const std::vector<faf::editor::ScenarioTeam> back = faf::editor::ScenarioTeams(two);
    ASSERT_EQ(back.size(), 2u);
    EXPECT_EQ(back[1].name, "Bottom");
    EXPECT_EQ(back[1].armies, std::vector<std::string>{"ARMY_3"});
    // Every team's armies, in order; the text after the block is kept.
    EXPECT_EQ(faf::editor::ScenarioArmies(two), (std::vector<std::string>{"ARMY_1", "ARMY_2", "ARMY_3"}));
    EXPECT_EQ(faf::editor::ScenarioExtraArmies(two).size(), 2u);
  }

  TEST(SaveFile, ScriptPlayableAreaIsSetAndRemoved)
  {
    const std::string script = "local ScenarioUtils = import('/lua/sim/ScenarioUtilities.lua')\n\nfunction OnPopulate()\n"
                               "\tScenarioUtils.InitializeArmies()\nend\n\nfunction OnStart(self)\nend\n";
    EXPECT_FALSE(faf::editor::ScriptPlayableArea(script).has_value());
    const std::string with = faf::editor::WithScriptPlayableArea(script, "AREA_1");
    ASSERT_TRUE(faf::editor::ScriptPlayableArea(with).has_value());
    EXPECT_EQ(*faf::editor::ScriptPlayableArea(with), "AREA_1");
    EXPECT_NE(with.find("local ScenarioFramework = import('/lua/ScenarioFramework.lua')"), std::string::npos);
    EXPECT_LT(with.find("InitializeArmies"), with.find("SetPlayableArea"));
    const std::string renamed = faf::editor::WithScriptPlayableArea(with, "AREA_2");
    EXPECT_EQ(*faf::editor::ScriptPlayableArea(renamed), "AREA_2");
    EXPECT_EQ(renamed.find("AREA_1"), std::string::npos);
    const std::string without = faf::editor::WithScriptPlayableArea(renamed, "");
    EXPECT_FALSE(faf::editor::ScriptPlayableArea(without).has_value());
  }
} // namespace
