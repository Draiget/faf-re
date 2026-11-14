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

  TEST(
    Mission,
    ATestRunStartsAtAStageAndItsTraceReadsBack
  )
  {
    MissionCompileOptions o;
    o.test = true;
    o.startStage = 2;
    EXPECT_TRUE(Has(CompileMission(TwoStages(), o), "Stage[ScenarioInfo.EditorStartStage or 2]()"));
    o.startStage = 9;
    EXPECT_TRUE(Has(CompileMission(TwoStages(), o), "Stage[ScenarioInfo.EditorStartStage or 2]()"))
      << "the last at most";
    o.test = false;
    EXPECT_TRUE(Has(CompileMission(TwoStages(), o), "    Stage[1]()")) << "a saved map starts at the first";
    MissionTraceId id;
    ASSERT_TRUE(ParseMissionTrace("stage.3", id));
    EXPECT_EQ(id.stage, 3);
    EXPECT_TRUE(id.section.empty());
    ASSERT_TRUE(ParseMissionTrace("2.ready.4.1!", id));
    EXPECT_EQ(id.stage, 2);
    EXPECT_EQ(id.section, "ready");
    EXPECT_EQ(id.path, (std::vector<int>{4, 1}));
    EXPECT_EQ(id.mark, '!');
    ASSERT_TRUE(ParseMissionTrace("1.enter.2~\r", id));
    EXPECT_EQ(id.mark, '~');
    EXPECT_FALSE(ParseMissionTrace("1.middle.2", id));
    EXPECT_FALSE(ParseMissionTrace("nonsense", id));
    EXPECT_FALSE(ParseMissionTrace("1.enter.0", id));
  }

  namespace
  {
    Mission WithABase()
    {
      Mission m = TwoStages();
      MissionBase b = NewMissionBase("North", "ARMY_2");
      b.groups = {{"NorthDefense", 100}, {"NorthFactories", 90}};
      b.engineers = {2, 4, 6};
      b.alwaysAssist = true;
      b.switchOn = {"Shields", "NotASwitch"};
      b.noBuild = {"Experimentals"};
      MissionOpAI o;
      o.name = "NorthLand";
      o.children = {"HeavyTanks", "Bombers"}; // Bombers isn't a land platoon: left out
      o.qty = {4, 6, 8};
      o.chains = {"Patrol"};
      o.lock = "DeathTimer";
      o.lockSecs = 90;
      o.cond[0] = "stage reached";
      o.condStage[0] = 2;
      o.cond[1] = "flag is set";
      o.condFlag[1] = "Alarm";
      b.opai.push_back(o);
      m.bases.push_back(b);
      m.stages[0].enter.push_back(Node("base_start", {{"base", "North"}}));
      return m;
    }
  } // namespace

  TEST(
    Mission,
    ABaseCompilesToABaseManagerWithItsAttacks
  )
  {
    const std::string lua = CompileMission(WithABase(), MissionCompileOptions{});
    EXPECT_TRUE(Has(lua, "local BaseManager = import('/lua/ai/opai/basemanager.lua')"));
    EXPECT_TRUE(Has(lua, "function Base.Start_North()"));
    EXPECT_TRUE(Has(lua, "if Base.Manager_North then return end"));
    EXPECT_LT(lua.find("if name == 'ARMY_2' then present = true end"), lua.find("local brain = GetArmyBrain('ARMY_2')"))
      << "an army that isn't in the game only warns";
    EXPECT_TRUE(Has(lua, "if not brain.PBMAddBuildLocation then"));
    EXPECT_TRUE(
      Has(lua, "bm:Initialize(brain, 'North', 'North_Marker', 40, { ['NorthDefense'] = 100, ['NorthFactories'] = 90 })")
    );
    EXPECT_TRUE(Has(lua, "bm:StartNonZeroBase({ { 2, 4, 6 }, { 0, 0, 0 } })"));
    EXPECT_TRUE(Has(lua, "bm:SetConstructionAlwaysAssist(true)"));
    EXPECT_TRUE(Has(lua, "bm:SetActive('Shields', true)"));
    EXPECT_FALSE(Has(lua, "NotASwitch")) << "an unknown switch is left out";
    EXPECT_TRUE(Has(lua, "bm:SetBuild('Experimentals', false)"));
    EXPECT_TRUE(Has(lua, "op = bm:AddOpAI('BasicLandAttack', 'NorthLand', {"));
    EXPECT_TRUE(Has(lua, "MasterPlatoonFunction = { '/lua/scenarioplatoonai.lua', 'PatrolChainPickerThread' },"));
    EXPECT_TRUE(Has(lua, "PlatoonData = { PatrolChains = { 'Patrol' } },"));
    EXPECT_TRUE(Has(lua, "op:SetChildQuantity({ 'HeavyTanks' }, ({ 4, 6, 8 })[Difficulty])"));
    EXPECT_TRUE(Has(lua, "op:SetLockingStyle('DeathTimer', { LockTimer = 90 })"));
    EXPECT_TRUE(Has(lua, "'MissionNumberGreaterOrEqual', { 2 })"));
    EXPECT_TRUE(Has(lua, "'CheckScenarioInfoVarTable', { 'Alarm' })"));
    EXPECT_TRUE(Has(lua, "Base.Start_North()\n")) << "the stage's node starts it";
    // The bases come before the stages start.
    EXPECT_LT(lua.find("function Base.Start_North()"), lua.find("ScenarioInfo.MissionNumber = 0"));
    // Starting empty, per difficulty.
    Mission m = WithABase();
    m.bases[0].startEmpty = true;
    m.bases[0].diff = true;
    const std::string empty = CompileMission(m, MissionCompileOptions{});
    EXPECT_TRUE(Has(empty, "bm:InitializeDifficultyTables(brain, 'North'"));
    EXPECT_TRUE(Has(empty, "bm:StartEmptyBase({ { 2, 4, 6 }, { 0, 0, 0 } })"));
    // A name that isn't one leaves no function.
    m.bases[0].name = "North'); os.exit(";
    EXPECT_FALSE(Has(CompileMission(m, MissionCompileOptions{}), "os.exit"));
  }

  TEST(
    Mission,
    BaseChecksFindWhatTheBaseManagerWouldMiss
  )
  {
    Mission m = WithABase();
    MissionFacts facts;
    facts.armies = {"ARMY_1", "ARMY_2"};
    facts.groups["ARMY_2"] = {"NorthDefense"};
    facts.chains = {"Patrol"};
    facts.markers = {"North_Marker"};
    std::vector<MissionProblem> p = CheckMission(m, facts);
    EXPECT_EQ(CountOf(p, "base North: army ARMY_2 has no group NorthFactories"), 1U);
    EXPECT_EQ(CountOf(p, "base North: there is no marker"), 0U);
    EXPECT_EQ(CountOf(p, "no stage starts it"), 0U);
    EXPECT_EQ(CountOf(p, "no base North"), 0U);
    m.bases[0].diff = true;
    m.bases[0].marker = "Nowhere";
    m.bases[0].opai[0].chains = {"Gone"};
    m.bases[0].opai.push_back(m.bases[0].opai[0]);
    m.bases.push_back(NewMissionBase("Spare", "ARMY_7"));
    m.stages[0].enter.push_back(Node("base_active", {{"base", "Missing"}, {"on", "true"}}));
    p = CheckMission(m, facts);
    EXPECT_EQ(CountOf(p, "army ARMY_2 has no group NorthDefense_D1"), 1U);
    EXPECT_EQ(CountOf(p, "base North: there is no marker Nowhere"), 1U);
    EXPECT_EQ(CountOf(p, "attack NorthLand: no chain Gone"), 2U);
    EXPECT_EQ(CountOf(p, "attack NorthLand: name used twice"), 1U);
    EXPECT_EQ(CountOf(p, "base Spare: army ARMY_7 is not in the army list"), 1U);
    EXPECT_EQ(CountOf(p, "base Spare: no build group"), 1U);
    EXPECT_EQ(CountOf(p, "base Spare: no stage starts it"), 1U);
    EXPECT_EQ(CountOf(p, "no base Missing"), 1U);
  }

  TEST(
    Mission,
    SavedBasesReadBack
  )
  {
    Mission m = WithABase();
    m.bases[0].radius = 55;
    m.bases[0].supportAcus = 2;
    m.bases[0].opai[0].master = "random patrol";
    m.bases[0].opai[0].condCount[1] = {12, 8, 3};
    Mission back;
    std::string error;
    ASSERT_TRUE(LoadMission(SaveMission(m), back, error)) << error;
    ASSERT_EQ(back.bases.size(), 1U);
    const MissionBase& b = back.bases[0];
    EXPECT_EQ(b.name, "North");
    EXPECT_EQ(b.marker, "North_Marker");
    EXPECT_DOUBLE_EQ(b.radius, 55);
    EXPECT_TRUE(b.alwaysAssist);
    EXPECT_FALSE(b.startEmpty);
    EXPECT_DOUBLE_EQ(b.supportAcus, 2);
    EXPECT_EQ(b.switchOn, (std::vector<std::string>{"Shields", "NotASwitch"}));
    ASSERT_EQ(b.groups.size(), 2U);
    EXPECT_EQ(b.groups[1].name, "NorthFactories");
    EXPECT_DOUBLE_EQ(b.groups[1].priority, 90);
    ASSERT_EQ(b.opai.size(), 1U);
    EXPECT_EQ(b.opai[0].master, "random patrol");
    EXPECT_EQ(b.opai[0].condFlag[1], "Alarm");
    EXPECT_DOUBLE_EQ(b.opai[0].condCount[1][2], 3);
    EXPECT_EQ(CompileMission(back, MissionCompileOptions{}), CompileMission(m, MissionCompileOptions{}));
    // Bases alone are still a mission to save.
    Mission only;
    only.bases.push_back(NewMissionBase("Solo", "ARMY_2"));
    EXPECT_FALSE(SaveMission(only).empty());
  }
} // namespace faf::editor
