// Which lobby settings make a map's script create a unit group (src/editor/doc/EdGroupOptions.cpp), read from the
// script's blocks and the map's _options.lua. The texts follow DualGap Adaptive v14's script and options.

#include "editor/doc/EdGroupOptions.h"
#include "TestEnv.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <sstream>

namespace
{
  using faf::editor::GroupLobbyRule;

  const char* const kOptions = R"lua(
options =
{
{
	default = 1,
	label = "Wreckage",
	help = "Scale amount of unit wrecks.",
	key = 'optional_wreckage',
	pref = 'optional_wreckage',
	values = {
		{ text = "disabled", help = "No wrecks.", key = 1, },
		{ text = "T3 wreckage", help = "Add T3 wreckage MID.", key = 2, },
	},
},
{
    default = 1,
    label = "Civilian Base",
    key = 'optional_civilian_base',
    values = {
        { text = "disabled", key = 1, },
        { text = "wrecks", key = 2, },
        { text = "operational", key = 3, },
    },
},
{
    default = 2,
    label = "Faction reclaim",
    key = 'optional_adaptive_faction_wreckage',
    values = {
        { text = "none", key = 1, },
        { text = "one", key = 2, },
        { text = "two", key = 3, },
    },
},
--[[
{
    default = 1,
    label = "Naval wreckage",
    key = 'optional_naval_wreckage',
    values = { { text = "none", key = 1, }, { text = "some", key = 2, }, },
},
]]--
{
    default = 1,
    label = "Jamming",
    key = 'jamming',
    values = { "off", "on" },
},
}
)lua";

  const char* const kScript = R"lua(
local optional_wreckage = ScenarioInfo.Options.optional_wreckage or 1
local optional_naval_wreckage = ScenarioInfo.Options.optional_naval_wreckage or 1
local optional_adaptive_faction_wreckage = ScenarioInfo.Options.optional_adaptive_faction_wreckage or 1
local optional_civilian_base = ScenarioInfo.Options.optional_civilian_base or 1

function OnPopulate()
    ScenarioUtils.InitializeArmies()
    OptionalUnits()
end

function OptionalUnits()
    if optional_wreckage > 1 then
        for w = 2, optional_wreckage do
            ScenarioUtils.CreateArmyGroup('ARMY_17', 'Optional_Wreckage_' .. w, true)
        end
    end
    if optional_naval_wreckage > 1 then
        for n = 2, optional_naval_wreckage do
            ScenarioUtils.CreateArmyGroup('ARMY_17', 'Optional_Wreckage_Naval_'..n, true)
        end
    end
    if(optional_adaptive_faction_wreckage > 1) then
        AddFactionReclaimBack(optional_adaptive_faction_wreckage)
    end
    if(optional_civilian_base == 2) then
        ScenarioUtils.CreateArmyGroup('ARMY_17', 'Optional_Civilian_Base_2', true)
    elseif(optional_civilian_base == 3) then
        ScenarioUtils.CreateArmyGroup('ARMY_17', 'Optional_Civilian_Base_2', false)
    else
        ScenarioUtils.CreateArmyGroup('ARMY_17', 'Civilian_Ruins', true)
    end
--[[    if(optional_civilian_base > 1) then
        ScenarioUtils.CreateArmyGroup('ARMY_17', 'Optional_Civilian_Commented', false)
    end]]
    if ScenarioInfo.Options.jamming == 'on' then
        ScenarioUtils.CreateArmyGroup('ARMY_17', 'Jamming', false)
    end
    ScenarioUtils.CreateArmyGroup('ARMY_17', 'Outpost', false)
end

function AddFactionReclaimBack(optional_adaptive_faction_wreckage)
    for _, army in ListArmies() do
        if( army == "ARMY_7") then
            ScenarioUtils.CreateArmyGroup('ARMY_17', 'Optional_Wreckage_Back_Top_UEF_2', true)
            if(optional_adaptive_faction_wreckage == 3) then
                ScenarioUtils.CreateArmyGroup('ARMY_17', 'Optional_Wreckage_Back_Top_UEF_3', true)
            end
        end
    end
end
)lua";

  GroupLobbyRule Rule(
    const char* const group
  )
  {
    return faf::editor::LobbyRuleOfGroup(kScript, faf::editor::ParseLobbyOptions(kOptions), group);
  }

  TEST(
    GroupOptions,
    OptionsFileWithoutCommentedOnes
  )
  {
    const auto options = faf::editor::ParseLobbyOptions(kOptions);
    ASSERT_EQ(options.size(), 4u);
    EXPECT_EQ(options[0].key, "optional_wreckage");
    EXPECT_EQ(options[0].label, "Wreckage");
    ASSERT_EQ(options[0].values.size(), 2u);
    EXPECT_EQ(options[0].values[1].text, "T3 wreckage");
    EXPECT_TRUE(options[0].values[1].number);
    EXPECT_EQ(options[0].values[1].numberKey, 2.0);
    EXPECT_EQ(options[0].defaultIndex, 1);
    // Plain values: their text is their key.
    EXPECT_EQ(options[3].key, "jamming");
    ASSERT_EQ(options[3].values.size(), 2u);
    EXPECT_EQ(options[3].values[1].key, "on");
    EXPECT_FALSE(options[3].values[1].number);
  }

  TEST(
    GroupOptions,
    ALoopOverTheOptionsValue
  )
  {
    const GroupLobbyRule rule = Rule("Optional_Wreckage_2");
    ASSERT_TRUE(rule.scriptNames);
    ASSERT_EQ(rule.keys, std::vector<std::string>{"optional_wreckage"});
    ASSERT_EQ(rule.cases.size(), 2u);
    EXPECT_EQ(rule.cases[0].made, GroupLobbyRule::Made::No);
    EXPECT_EQ(rule.cases[1].made, GroupLobbyRule::Made::Yes);
    EXPECT_TRUE(rule.cases[1].asWreck);
    EXPECT_FALSE(rule.cases[1].asUnit);
    const auto lines = faf::editor::DescribeLobbyRule(rule, faf::editor::ParseLobbyOptions(kOptions));
    ASSERT_EQ(lines.size(), 3u);
    EXPECT_EQ(lines[0], "Lobby option \"Wreckage\" (optional_wreckage):");
    EXPECT_EQ(lines[1], "  \"disabled\" (default): not created");
    EXPECT_EQ(lines[2], "  \"T3 wreckage\": created as wrecks");
    // The loop never reaches 3: no value makes Optional_Wreckage_3.
    EXPECT_TRUE(Rule("Optional_Wreckage_3").Never());
  }

  TEST(
    GroupOptions,
    AnOptionTheLobbyDoesntOffer
  )
  {
    // optional_naval_wreckage is commented out in _options.lua: always the script's default 1, so never made.
    const GroupLobbyRule rule = Rule("Optional_Wreckage_Naval_2");
    ASSERT_EQ(rule.keys, std::vector<std::string>{"optional_naval_wreckage"});
    EXPECT_EQ(rule.optionIndex[0], -1);
    EXPECT_EQ(rule.scriptDefault[0], "1");
    EXPECT_TRUE(rule.Never());
    const auto lines = faf::editor::DescribeLobbyRule(rule, faf::editor::ParseLobbyOptions(kOptions));
    ASSERT_EQ(lines.size(), 2u);
    EXPECT_NE(lines[0].find("doesn't offer"), std::string::npos);
    EXPECT_EQ(lines[1], "No lobby setting creates it: never in a game.");
  }

  TEST(
    GroupOptions,
    IfElseifElse
  )
  {
    const GroupLobbyRule base = Rule("Optional_Civilian_Base_2");
    ASSERT_EQ(base.cases.size(), 3u);
    EXPECT_EQ(base.cases[0].made, GroupLobbyRule::Made::No);
    EXPECT_EQ(base.cases[1].made, GroupLobbyRule::Made::Yes);
    EXPECT_TRUE(base.cases[1].asWreck);
    EXPECT_FALSE(base.cases[1].asUnit);
    EXPECT_EQ(base.cases[2].made, GroupLobbyRule::Made::Yes);
    EXPECT_FALSE(base.cases[2].asWreck);
    EXPECT_TRUE(base.cases[2].asUnit);
    // The else branch: only when neither earlier condition holds.
    const GroupLobbyRule ruins = Rule("Civilian_Ruins");
    ASSERT_EQ(ruins.cases.size(), 3u);
    EXPECT_EQ(ruins.cases[0].made, GroupLobbyRule::Made::Yes);
    EXPECT_EQ(ruins.cases[1].made, GroupLobbyRule::Made::No);
    EXPECT_EQ(ruins.cases[2].made, GroupLobbyRule::Made::No);
  }

  TEST(
    GroupOptions,
    ThroughAFunctionAndTheGame
  )
  {
    // Called only when the option is above 1; inside, who plays ARMY_7 decides: "maybe".
    const GroupLobbyRule top = Rule("Optional_Wreckage_Back_Top_UEF_2");
    ASSERT_EQ(top.keys, std::vector<std::string>{"optional_adaptive_faction_wreckage"});
    ASSERT_EQ(top.cases.size(), 3u);
    EXPECT_EQ(top.cases[0].made, GroupLobbyRule::Made::No);
    EXPECT_EQ(top.cases[1].made, GroupLobbyRule::Made::Maybe);
    EXPECT_EQ(top.cases[2].made, GroupLobbyRule::Made::Maybe);
    const GroupLobbyRule three = Rule("Optional_Wreckage_Back_Top_UEF_3");
    EXPECT_EQ(three.cases[1].made, GroupLobbyRule::Made::No);
    EXPECT_EQ(three.cases[2].made, GroupLobbyRule::Made::Maybe);
  }

  TEST(
    GroupOptions,
    DirectReadsAndNoOption
  )
  {
    const GroupLobbyRule jamming = Rule("Jamming");
    ASSERT_EQ(jamming.keys, std::vector<std::string>{"jamming"});
    EXPECT_EQ(jamming.cases[0].made, GroupLobbyRule::Made::No);
    EXPECT_EQ(jamming.cases[1].made, GroupLobbyRule::Made::Yes);
    const GroupLobbyRule outpost = Rule("Outpost");
    EXPECT_TRUE(outpost.keys.empty());
    ASSERT_EQ(outpost.cases.size(), 1u);
    EXPECT_EQ(outpost.cases[0].made, GroupLobbyRule::Made::Yes);
    // Commented-out code creates nothing.
    EXPECT_FALSE(Rule("Optional_Civilian_Commented").scriptNames);
    EXPECT_FALSE(Rule("Spare").scriptNames);
  }

  const faf::editor::SpawnTarget* Find(
    const std::vector<faf::editor::SpawnTarget>& targets,
    const std::string& name
  )
  {
    for (const auto& target : targets) {
      if (target.path.back() == name) {
        return &target;
      }
    }
    return nullptr;
  }

  TEST(
    GroupOptions,
    SpawnTargets
  )
  {
    const auto targets =
      faf::editor::SpawnTargets(kScript, kOptions, "ARMY_17", {{"Optional_Wreckage_2"}, {"Base", "Civilian_Ruins"}});
    // An existing level: where it is, and the value that makes it.
    const auto* level2 = Find(targets, "Optional_Wreckage_2");
    ASSERT_NE(level2, nullptr);
    EXPECT_TRUE(level2->exists);
    EXPECT_EQ(level2->when, "Wreckage = \"T3 wreckage\"");
    EXPECT_TRUE(level2->wreck);
    EXPECT_TRUE(level2->optionsWith.empty());
    // The next level: a value added to the option, checked to make it.
    const auto* level3 = Find(targets, "Optional_Wreckage_3");
    ASSERT_NE(level3, nullptr);
    EXPECT_FALSE(level3->exists);
    EXPECT_EQ(level3->optionsChange, "adds the value \"level 2\" to \"Wreckage\"");
    EXPECT_EQ(level3->when, "Wreckage = \"level 2\"");
    const auto withLevel = faf::editor::ParseLobbyOptions(level3->optionsWith);
    ASSERT_EQ(withLevel.size(), 4u);
    ASSERT_EQ(withLevel[0].values.size(), 3u);
    EXPECT_EQ(withLevel[0].values[1].text, "T3 wreckage"); // the values there keep their texts
    EXPECT_EQ(withLevel[0].values[1].help, "Add T3 wreckage MID.");
    // A looped option the lobby lacks: the option written.
    const auto* naval = Find(targets, "Optional_Wreckage_Naval_2");
    ASSERT_NE(naval, nullptr);
    EXPECT_NE(naval->optionsChange.find("adds the lobby option \"Optional naval wreckage\""), std::string::npos);
    EXPECT_EQ(faf::editor::ParseLobbyOptions(naval->optionsWith).size(), 5u);
    // Names the script writes; a nested existing group keeps its path.
    const auto* ruins = Find(targets, "Civilian_Ruins");
    ASSERT_NE(ruins, nullptr);
    EXPECT_EQ(ruins->path, (std::vector<std::string>{"Base", "Civilian_Ruins"}));
    EXPECT_EQ(ruins->when, "Civilian Base = \"disabled\"");
    EXPECT_EQ(Find(targets, "Optional_Civilian_Base_2")->when, "Civilian Base = \"wrecks\"");
    EXPECT_EQ(Find(targets, "Jamming")->when, "Jamming = \"on\"");
    EXPECT_EQ(Find(targets, "Outpost")->when, "every game");
    EXPECT_EQ(
      Find(targets, "Optional_Wreckage_Back_Top_UEF_2")->when,
      "Faction reclaim = \"one\" (and the game: slots, factions)"
    );
    // Commented-out code offers nothing; another army gets none of ARMY_17's groups.
    EXPECT_EQ(Find(targets, "Optional_Civilian_Commented"), nullptr);
    EXPECT_TRUE(faf::editor::SpawnTargets(kScript, kOptions, "ARMY_1", {}).empty());
  }

  // The real map, when its folder is given (FAF_DUALGAP_DIR: dualgap_adaptive.v0014).
  TEST(
    GroupOptions,
    DualGapAdaptive
  )
  {
    const std::string dir = faf::editor::test::EnvText("FAF_DUALGAP_DIR");
    if (dir.empty()) {
      GTEST_SKIP() << "FAF_DUALGAP_DIR is not set (the folder of dualgap_adaptive.v0014)";
    }
    const auto read = [&](const char* const name) {
      std::ifstream in(dir + "/" + name, std::ios::binary);
      std::stringstream text;
      text << in.rdbuf();
      return text.str();
    };
    const std::string script = read("DualGap_Adaptive_script.lua");
    const auto options = faf::editor::ParseLobbyOptions(read("DualGap_Adaptive_options.lua"));
    ASSERT_FALSE(script.empty());
    // Its lobby: 8 options after the commented-out ones are left out.
    EXPECT_EQ(options.size(), 8u);
    const GroupLobbyRule wreckage = faf::editor::LobbyRuleOfGroup(script, options, "Optional_Wreckage_2");
    ASSERT_EQ(wreckage.keys, std::vector<std::string>{"optional_wreckage"});
    ASSERT_EQ(wreckage.cases.size(), 2u);
    EXPECT_EQ(wreckage.cases[0].made, GroupLobbyRule::Made::No);
    EXPECT_EQ(wreckage.cases[1].made, GroupLobbyRule::Made::Yes);
    EXPECT_TRUE(wreckage.cases[1].asWreck);
    // The options v14 commented out: their groups never appear.
    EXPECT_TRUE(faf::editor::LobbyRuleOfGroup(script, options, "Optional_Wreckage_Naval_2").Never());
    EXPECT_TRUE(faf::editor::LobbyRuleOfGroup(script, options, "Optional_Wreckage_Middle_2").Never());
    EXPECT_TRUE(faf::editor::LobbyRuleOfGroup(script, options, "Optional_Civilian_Base_2").Never());
    EXPECT_TRUE(faf::editor::LobbyRuleOfGroup(script, options, "Optional_Wreckage_Back_Top_UEF_2").Never());
    for (const std::string& line : faf::editor::DescribeLobbyRule(wreckage, options)) {
      std::printf("%s\n", line.c_str());
    }
    // What the Properties panel offers ARMY_17's units.
    for (const auto& target : faf::editor::SpawnTargets(
           script, read("DualGap_Adaptive_options.lua"), "ARMY_17", {{"Optional_Wreckage_2"}}
         )) {
      std::printf(
        "%s%s: %s%s%s\n",
        target.path.back().c_str(),
        target.exists ? "" : " (new)",
        target.when.c_str(),
        target.optionsChange.empty() ? "" : "; ",
        target.optionsChange.c_str()
      );
    }
  }
} // namespace
