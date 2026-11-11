// An adaptive map's lobby options as the Adaptive Map window shows them (src/editor/doc/EdAdaptiveModel.cpp).

#include "editor/doc/EdAdaptiveModel.h"

#include <gtest/gtest.h>

namespace
{
  using faf::editor::AdaptiveOption;

  const char* const kScript = R"lua(
local Tables = import('/maps/x/x_tables.lua')
local optional_wreckage = ScenarioInfo.Options.optional_wreckage or 1
local optional_naval_wreckage = ScenarioInfo.Options.optional_naval_wreckage or 1
local jamming = ScenarioInfo.Options.jamming or 1
function OptionalUnits()
    for w = 2, optional_wreckage do
        ScenarioUtils.CreateArmyGroup('ARMY_17', 'Optional_Wreckage_' .. w, true)
    end
    for n = 2, optional_naval_wreckage do
        ScenarioUtils.CreateArmyGroup('ARMY_17', 'Optional_Wreckage_Naval_'..n, true)
    end
    if jamming == 2 then
        ScenarioUtils.CreateArmyGroup('ARMY_17', 'Jamming', false)
    end
end
)lua";

  const char* const kOptions = R"lua(options = {
{ default = 1, label = "Middle mexes", help = "More mexes.", key = 'middle_mexes', values = {
    { text = "none", help = "", key = 1, }, { text = "some", help = "", key = 2, }, }, },
{ default = 2, label = "Wreckage", help = "Wrecks.", key = 'optional_wreckage', values = {
    { text = "disabled", help = "No wrecks.", key = 1, }, { text = "T3 wreckage", help = "Mid.", key = 2, }, }, },
{ default = 1, label = "Jamming", key = 'jamming', values = {
    { text = "off", key = 1, }, { text = "on", key = 2, }, }, },
{ default = 1, label = "Mode", key = 'mode', values = { 'fast', 'slow' }, },
}
)lua";

  TEST(AdaptiveModel, OptionsByKindInTheLobbysOrder)
  {
    faf::editor::AdaptiveTables tables;
    tables.options = {{"middleMexes", {{"Mass 07"}}}, {"sideMexes", {{"Mass 09"}, {}}}};
    const auto lobby = faf::editor::ParseLobbyOptions(kOptions);
    const auto options = faf::editor::AdaptiveOptionsOf(kScript, lobby, tables, true);
    ASSERT_EQ(options.size(), 6u);
    EXPECT_EQ(options[0].key, "middle_mexes");
    EXPECT_EQ(options[0].kind, AdaptiveOption::Kind::Mexes);
    EXPECT_EQ(options[0].table, "middleMexes");
    EXPECT_TRUE(options[0].scriptReads); // the adaptive script reads every table's option
    EXPECT_EQ(options[1].kind, AdaptiveOption::Kind::UnitLevels);
    EXPECT_EQ(options[1].loop.prefix, "Optional_Wreckage_");
    EXPECT_EQ(options[1].loop.army, "ARMY_17");
    EXPECT_EQ(options[1].loop.from, 2);
    EXPECT_TRUE(options[1].loop.wreck);
    EXPECT_EQ(options[1].title, "Wreckage");
    EXPECT_EQ(options[2].kind, AdaptiveOption::Kind::Other);
    EXPECT_TRUE(options[2].scriptReads);
    EXPECT_FALSE(options[3].scriptReads); // 'mode': in the lobby, read by nothing
    // Not in the lobby: a table with groups, then a loop.
    EXPECT_EQ(options[4].key, "side_mexes");
    EXPECT_EQ(options[4].lobby, -1);
    EXPECT_EQ(options[4].title, "Side mexes");
    EXPECT_EQ(options[5].key, "optional_naval_wreckage");
    EXPECT_EQ(options[5].kind, AdaptiveOption::Kind::UnitLevels);
    EXPECT_EQ(options[5].title, "Optional naval wreckage");
  }

  TEST(AdaptiveModel, WhatAChoiceAdds)
  {
    const auto lobby = faf::editor::ParseLobbyOptions(kOptions);
    EXPECT_EQ(faf::editor::TableGroupOfChoice(lobby[0].values[0]), -1);
    EXPECT_EQ(faf::editor::TableGroupOfChoice(lobby[0].values[1]), 0);
    faf::editor::ScriptGroupLoop loop;
    loop.prefix = "Optional_Wreckage_";
    loop.from = 2;
    EXPECT_EQ(faf::editor::LoopGroupOfChoice(loop, lobby[1].values[0]), "");
    EXPECT_EQ(faf::editor::LoopGroupOfChoice(loop, lobby[1].values[1]), "Optional_Wreckage_2");
    // Jamming "on" makes the Jamming group, as units; "off" nothing.
    const auto on = faf::editor::GroupsMadeByChoice(kScript, lobby, "jamming", 1);
    ASSERT_EQ(on.size(), 1u);
    EXPECT_EQ(on[0].group, "Jamming");
    EXPECT_TRUE(on[0].unit);
    EXPECT_FALSE(on[0].maybe);
    EXPECT_TRUE(faf::editor::GroupsMadeByChoice(kScript, lobby, "jamming", 0).empty());
  }

  TEST(AdaptiveModel, AnOptionWrittenBackKeepsItsKeys)
  {
    auto lobby = faf::editor::ParseLobbyOptions(kOptions);
    // Renamed choice, new default, a level added: the rest as it was.
    lobby[1].values[1].text = "T3 wrecks";
    lobby[1].defaultIndex = 1;
    lobby[1].values.push_back(faf::editor::NextLevelValue(lobby[1], "level 2"));
    const std::string out = faf::editor::WithOption(kOptions, lobby[1]);
    const auto back = faf::editor::ParseLobbyOptions(out);
    ASSERT_EQ(back.size(), 4u);
    EXPECT_EQ(back[1].label, "Wreckage");
    EXPECT_EQ(back[1].help, "Wrecks.");
    EXPECT_EQ(back[1].defaultIndex, 1);
    ASSERT_EQ(back[1].values.size(), 3u);
    EXPECT_EQ(back[1].values[1].text, "T3 wrecks");
    EXPECT_EQ(back[1].values[1].help, "Mid.");
    EXPECT_EQ(back[1].values[2].numberKey, 3.0);
    // String keys stay strings.
    const std::string mode = faf::editor::WithOption(kOptions, lobby[3]);
    const auto modeBack = faf::editor::ParseLobbyOptions(mode);
    ASSERT_EQ(modeBack[3].values.size(), 2u);
    EXPECT_FALSE(modeBack[3].values[0].number);
    EXPECT_EQ(modeBack[3].values[0].key, "fast");
    // The other options untouched.
    EXPECT_NE(out.find("key = 'middle_mexes'"), std::string::npos);
    EXPECT_EQ(back[0].values.size(), 2u);
  }

  TEST(AdaptiveModel, ReadableKeys)
  {
    EXPECT_EQ(faf::editor::ReadableKey("optional_naval_wreckage"), "Optional naval wreckage");
    EXPECT_EQ(faf::editor::ReadableKey("middleMexes"), "Middle mexes");
  }
} // namespace
