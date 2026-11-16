// The fifth comparison with FAF Studio (field target): mission flags in the test play, dialogue lines with a
// voice-over, video and portrait.

#include "editor/tools/EdMission.h"

#include <gtest/gtest.h>

#include <string>

namespace
{
  using namespace faf::editor;

  TEST(
    RoundSevenField,
    FlagsComeFromTheLiveStateAndAreSetByName
  )
  {
    MissionLive live;
    ASSERT_TRUE(ParseMissionLive("EDMISSION live tick 40|stage 2|flag ATTACK_NOW=1|flag B=0", live));
    ASSERT_EQ(live.flags.size(), 2U);
    EXPECT_EQ(live.flags[0].first, "ATTACK_NOW");
    EXPECT_TRUE(live.flags[0].second);
    EXPECT_FALSE(live.flags[1].second);
    EXPECT_NE(MissionLiveQuery().find("VarTable"), std::string::npos);
    std::string command;
    ASSERT_TRUE(MissionSetFlag("ATTACK_NOW", false, command));
    EXPECT_NE(command.find("ScenarioInfo.VarTable['ATTACK_NOW'] = false"), std::string::npos) << command;
    EXPECT_FALSE(MissionSetFlag("bad name'", true, command)) << "only letters, digits and _";
  }

  TEST(
    RoundSevenField,
    DialogueLinesKeepTheirVoiceOverVideoAndPortrait
  )
  {
    Mission m;
    MissionDialogue d;
    d.name = "Intro";
    MissionDialogueLine line;
    line.text = "Hold the line";
    line.speaker = "Commander";
    line.bank = "XGG";
    line.cue = "XGG_Brackman_001";
    line.vid = "UEF_Commander.sfd";
    line.faction = "UEF";
    d.lines.push_back(line);
    m.dialogues.push_back(d);
    const std::string script = CompileMission(m, MissionCompileOptions{});
    EXPECT_NE(script.find("bank = 'XGG'"), std::string::npos);
    EXPECT_NE(script.find("cue = 'XGG_Brackman_001'"), std::string::npos);
    EXPECT_NE(script.find("vid = 'UEF_Commander.sfd'"), std::string::npos);
    EXPECT_NE(script.find("faction = 'UEF'"), std::string::npos);
    const auto loaded = LoadMission(SaveMission(m));
    ASSERT_TRUE(loaded) << loaded.error();
    const Mission& back = *loaded;
    ASSERT_EQ(back.dialogues.size(), 1U);
    ASSERT_EQ(back.dialogues[0].lines.size(), 1U);
    EXPECT_EQ(back.dialogues[0].lines[0].cue, "XGG_Brackman_001");
    EXPECT_EQ(back.dialogues[0].lines[0].faction, "UEF");
  }
} // namespace
