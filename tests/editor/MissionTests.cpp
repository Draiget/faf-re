#include "editor/tools/EdMission.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>
#include <limits>

namespace faf::editor
{
  namespace
  {
    MissionNode Node(
      const std::string& type,
      std::map<std::string, std::string> values,
      std::vector<MissionNode> children = {}
    )
    {
      MissionNode n = NewMissionNode(type);
      for (auto& [key, value] : values) {
        n.p[key] = value;
      }
      n.children = std::move(children);
      return n;
    }

    bool Has(
      const std::string& text,
      const std::string& part
    )
    {
      return text.find(part) != std::string::npos;
    }

    std::size_t CountOf(
      const std::vector<MissionProblem>& problems,
      const std::string& words
    )
    {
      return static_cast<std::size_t>(std::count_if(problems.begin(), problems.end(), [&](const MissionProblem& p) {
        return p.text.find(words) != std::string::npos;
      }));
    }

    /** Two stages: spawn and kill, then a line and a win. */
    Mission TwoStages()
    {
      Mission m;
      MissionStage first;
      first.name = "Attack";
      first.enter.push_back(Node("spawn", {{"army", "ARMY_2"}, {"group", "ATTACK"}, {"var", "attackers"}}));
      first.ready.push_back(Node("obj_kill", {{"var", "attackers"}}));
      MissionStage second;
      second.name = "Win";
      second.enter.push_back(Node("dialogue", {{"text", "Well done"}}));
      second.enter.push_back(Node("end", {{"result", "win"}}));
      m.stages = {first, second};
      return m;
    }
  } // namespace

  TEST(
    Mission,
    ValuesReachTheScriptOnlyQuoted
  )
  {
    EXPECT_EQ(MissionQuote("it's\n"), "'it\\'s\\010'");
    EXPECT_EQ(MissionQuote("a\\b"), "'a\\\\b'");
    EXPECT_EQ(MissionNumber(std::numeric_limits<double>::quiet_NaN(), 7), "7");
    EXPECT_EQ(MissionNumber(2.5), "2.500");
    EXPECT_EQ(MissionNumber(3), "3");
    EXPECT_TRUE(MissionIsName("V1_x"));
    EXPECT_FALSE(MissionIsName("end"));
    EXPECT_FALSE(MissionIsName("1a"));
    EXPECT_FALSE(MissionIsName("a b"));
    EXPECT_EQ(MissionVar("bad name"), "V.UNSET");
    EXPECT_EQ(MissionExpr("categories.TECH3 * categories.LAND", "X", nullptr), "(categories.TECH3 * categories.LAND)");
    EXPECT_EQ(MissionExpr("x) os.exit(", "X", nullptr), "X") << "a second expression";
    EXPECT_EQ(MissionExpr("{1}", "X", nullptr), "X") << "a table";
    EXPECT_EQ(MissionExpr("a -- b", "X", nullptr), "X") << "a comment";
    EXPECT_EQ(MissionExpr("", "X", nullptr), "X");
    // A node with values out of range gets the defaults.
    const MissionNodeType* wait = FindMissionNodeType("wait");
    ASSERT_NE(wait, nullptr);
    int fixed = 0;
    const MissionNode clean = CleanMissionNode(Node("wait", {{"seconds", "nan"}}), *wait, &fixed);
    EXPECT_EQ(fixed, 1);
    EXPECT_EQ(clean.p.at("seconds"), "10");
    EXPECT_GE(MissionNodeTypes().size(), 40U);
  }

  TEST(
    Mission,
    StagesCompileToTheScript
  )
  {
    Mission m = TwoStages();
    m.stages[1].enter[0].p["text"] = "x') os.execute('boom') --";
    MissionCompileOptions o;
    o.hasArea1 = true;
    std::vector<MissionProblem> problems;
    const std::string s = CompileMission(m, o, &problems);
    EXPECT_TRUE(problems.empty());
    EXPECT_TRUE(Has(s, "Stage[1] = function()"));
    EXPECT_TRUE(Has(s, "    V.attackers = ScenarioUtils.CreateArmyGroup('ARMY_2', 'ATTACK')"));
    EXPECT_TRUE(Has(s, "obj = Objectives.Kill('primary', 'incomplete', 'Destroy the enemy'"));
    EXPECT_TRUE(Has(
      s, "Objectives.CreateGroup('Stage1', function() ForkThread(function() WaitTicks(1) ForkThread(Stage[2]) end) end)"
    )) << "the objectives start the next stage";
    EXPECT_TRUE(Has(s, "    ScenarioFramework.EndOperation(true, true, true)"));
    EXPECT_FALSE(Has(s, "    ForkThread(Stage[3])")) << "no stage after the last";
    EXPECT_TRUE(Has(s, "text = 'x\\') os.execute(\\'boom\\') --'")) << "a hostile text stays one string";
    EXPECT_TRUE(Has(s, "ScenarioFramework.SetPlayableArea('AREA_1', false)"));
    EXPECT_TRUE(Has(s, "function OnStart(self)\n    ForkThread(EditorMissionStart)\nend"));
    EXPECT_FALSE(Has(s, "EdTrace")) << "a saved map has no test hooks";
    // A trigger with a child: the stage guard keeps it quiet after the stage moved on; a test run traces the nodes.
    m.stages[0].ready.push_back(Node("trg_timer", {{"seconds", "45"}}, {Node("dialogue", {{"text", "Hurry"}})}));
    o.test = true;
    const std::string t = CompileMission(m, o);
    EXPECT_TRUE(
      Has(t, "    Timer(function()\n        if ScenarioInfo.MissionNumber ~= 1 then EdTrace('1.ready.2~') return end")
    );
    EXPECT_TRUE(Has(t, "    end, 45)"));
    EXPECT_TRUE(Has(t, "EdTrace('1.ready.1')"));
    EXPECT_TRUE(Has(t, "Stage[ScenarioInfo.EditorStartStage or 1]()"));
    // A stage without objectives or an exit starts the next one at once; with a failsafe it waits for the timer.
    Mission plain;
    plain.stages.resize(2);
    plain.stages[0].enter.push_back(Node("wait", {{"seconds", "5"}}));
    plain.stages[1].enter.push_back(Node("end", {}));
    EXPECT_TRUE(Has(CompileMission(plain, MissionCompileOptions{}), "    Wait(5)\n    ForkThread(Stage[2])\nend"));
    plain.stages[0].failsafe = 90;
    const std::string failsafe = CompileMission(plain, MissionCompileOptions{});
    EXPECT_TRUE(Has(failsafe, "    Timer(function() ForkThread(Stage[2]) end, 90)"));
    EXPECT_FALSE(Has(failsafe, "    Wait(5)\n    ForkThread(Stage[2])"));
  }

  TEST(
    Mission,
    TheScriptsRegionIsWrittenReplacedOrLeftAlone
  )
  {
    const Mission m = TwoStages();
    MissionPatch status = MissionPatch::None;
    const std::string script = "-- my map\n";
    const std::string first = PatchMissionScript(script, m, MissionCompileOptions{}, status);
    EXPECT_EQ(status, MissionPatch::Written);
    EXPECT_TRUE(Has(first, "-- my map\n"));
    EXPECT_TRUE(Has(first, "-- >>> EDITOR MISSION v1 (generated"));
    EXPECT_TRUE(Has(first, "-- <<< EDITOR MISSION"));
    // Again: the same text (the region replaced by itself).
    EXPECT_EQ(PatchMissionScript(first, m, MissionCompileOptions{}, status), first);
    EXPECT_EQ(status, MissionPatch::Written);
    // Edited by hand inside the region: left alone.
    std::string edited = first;
    edited.replace(edited.find("Stage[1] = function()"), 5, "Phase");
    EXPECT_EQ(PatchMissionScript(edited, m, MissionCompileOptions{}, status), edited);
    EXPECT_EQ(status, MissionPatch::Detached);
    // A script with its own OnStart gets the stages but no entry functions; no mission: nothing written.
    const std::string own = "function OnPopulate() end\nfunction OnStart(self) DoMine() end\n" + std::string(600, ' ');
    const std::string withOwn = PatchMissionScript(own, m, MissionCompileOptions{}, status);
    EXPECT_FALSE(Has(withOwn.substr(own.size()), "function OnStart"));
    EXPECT_TRUE(Has(withOwn, "function EditorMissionStart()"));
    EXPECT_EQ(PatchMissionScript(script, Mission{}, MissionCompileOptions{}, status), script);
    EXPECT_EQ(status, MissionPatch::None);
  }

  TEST(
    Mission,
    ChecksFindWhatWouldBreakTheMission
  )
  {
    Mission m;
    m.stages.resize(2);
    m.stages[0].enter.push_back(Node("group_patrol", {{"var", "late"}, {"chain", "NoSuchChain"}}));
    m.stages[0].enter.push_back(Node("spawn", {{"army", "ARMY_2"}, {"group", "ATTACK"}, {"var", "late"}}));
    m.stages[0].enter.push_back(Node("coop_unitcap", {}));
    m.stages[0].enter.push_back(Node("teleport", {}));
    m.stages[0].enter.push_back(Node("restrict", {{"army", "ARMY_9"}, {"categories", "os.exit()"}}));
    m.stages[1].enter.push_back(Node("next_stage", {}));
    MissionFacts facts;
    facts.armies = {"ARMY_1", "ARMY_2"};
    facts.groups["ARMY_2"] = {"ATTACK"};
    facts.chains = {"Patrol"};
    const std::vector<MissionProblem> p = CheckMission(m, facts);
    EXPECT_EQ(CountOf(p, "variable late is read before any node sets it"), 1U);
    EXPECT_EQ(CountOf(p, "no chain NoSuchChain"), 1U);
    EXPECT_EQ(CountOf(p, "a coop node in a campaign mission"), 1U);
    EXPECT_EQ(CountOf(p, "unknown node type"), 1U);
    EXPECT_EQ(CountOf(p, "no army ARMY_9"), 1U);
    EXPECT_EQ(CountOf(p, "is not one category expression"), 0U)
      << "os.exit() is of the alphabet (no Lua here to try it)";
    EXPECT_EQ(CountOf(p, "there is no next stage"), 1U);
    EXPECT_EQ(CountOf(p, "the mission never ends"), 1U);
    EXPECT_EQ(CountOf(TwoStages().stages.empty() ? p : CheckMission(TwoStages(), facts), "never ends"), 0U);
  }

  TEST(
    Mission,
    SavedMissionReadsBack
  )
  {
    Mission m = TwoStages();
    m.mode = "both";
    m.stages[0].failsafe = 120;
    m.stages[0].ready.push_back(
      Node("trg_timer", {{"seconds", "30"}}, {Node("raw", {{"code", "local t = { \"}\" }\nLOG('a \\\\ b')"}})})
    );
    m.dialogues.push_back({"Intro", {{"Commander, \"welcome\" {", "HQ", 4}}});
    const std::string text = SaveMission(m);
    Mission back;
    std::string error;
    ASSERT_TRUE(LoadMission(text, back, error)) << error;
    EXPECT_EQ(back.mode, "both");
    ASSERT_EQ(back.stages.size(), 2U);
    EXPECT_EQ(back.stages[0].name, "Attack");
    EXPECT_DOUBLE_EQ(back.stages[0].failsafe, 120);
    ASSERT_EQ(back.stages[0].ready.size(), 2U);
    ASSERT_EQ(back.stages[0].ready[1].children.size(), 1U);
    EXPECT_EQ(back.stages[0].ready[1].children[0].p.at("code"), "local t = { \"}\" }\nLOG('a \\\\ b')");
    EXPECT_EQ(back.stages[0].enter[0].p.at("var"), "attackers");
    ASSERT_EQ(back.dialogues.size(), 1U);
    EXPECT_EQ(back.dialogues[0].lines[0].text, "Commander, \"welcome\" {");
    EXPECT_EQ(back.dialogues[0].lines[0].speaker, "HQ");
    EXPECT_EQ(CompileMission(back, MissionCompileOptions{}), CompileMission(m, MissionCompileOptions{}))
      << "the same script from the saved mission";
    EXPECT_EQ(SaveMission(Mission{}), "");
    EXPECT_FALSE(LoadMission("{}", back, error));
  }
} // namespace faf::editor
