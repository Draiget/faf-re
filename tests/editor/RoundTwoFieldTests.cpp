// The FAF Studio features of the editor's second round that need the field library: kept paths, the map skeleton, the
// detail pass's density, the mission import, the JSON tree and the icon comparison.

#include "editor/doc/EdJsonTree.h"
#include "editor/tools/EdDetailPass.h"
#include "editor/tools/EdKeptPaths.h"
#include "editor/tools/EdMissionImport.h"
#include "editor/tools/EdSkeleton.h"
#include "editor/tools/EdUnitIcon.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

namespace faf::editor
{
  namespace
  {
    constexpr int kSide = 129;

    std::vector<std::uint16_t> Flat(
      const float units
    )
    {
      return std::vector<std::uint16_t>(
        static_cast<std::size_t>(kSide) * kSide, static_cast<std::uint16_t>(units * 128.0f)
      );
    }

    float Ground(
      float,
      float
    )
    {
      return 20.0f;
    }
  } // namespace

  TEST(
    JsonTree,
    ParsesAndWritesBack
  )
  {
    const auto parsed = ParseJsonTree(R"({"a": [1, 2.5, "x\ny"], "b": {"c": true, "d": null}})");
    ASSERT_TRUE(parsed) << parsed.error();
    const JsonTree& root = *parsed;
    EXPECT_EQ(root.Get("a")->items.size(), 3U);
    EXPECT_DOUBLE_EQ(root.Get("a")->items[1].n, 2.5);
    EXPECT_EQ(root.Get("a")->items[2].s, "x\ny");
    EXPECT_TRUE(root.Get("b")->Bool("c", false));
    const auto again = ParseJsonTree(WriteJsonTree(root));
    ASSERT_TRUE(again) << again.error();
    EXPECT_EQ(WriteJsonTree(*again), WriteJsonTree(root));
    EXPECT_FALSE(ParseJsonTree("{\"a\": }"));
  }

  TEST(
    KeptPaths,
    SampledCurvePassesThroughItsPointsAndCarriesWidths
  )
  {
    KeptPath path = NewKeptPath(KeptPathMode::Carve, false, "p1");
    AddKeptPathPoint(path, 20.0f, 20.0f, Ground);
    AddKeptPathPoint(path, 60.0f, 40.0f, Ground);
    AddKeptPathPoint(path, 100.0f, 30.0f, Ground);
    path.points[2].w = 12.0f;
    const KeptPathSamples S = SampleKeptPath(path, 1.0f);
    ASSERT_GT(S.Count(), 50U);
    EXPECT_NEAR(S.x.front(), 20.0f, 1e-3f);
    EXPECT_NEAR(S.x.back(), 100.0f, 1e-3f);
    EXPECT_NEAR(S.w.back(), 12.0f, 1e-3f);
    EXPECT_GT(S.s.back(), 80.0f);
    // Bezier gives the same ends.
    path.bezier = true;
    const KeptPathSamples B = SampleKeptPath(path, 1.0f);
    EXPECT_NEAR(B.z.back(), 30.0f, 1e-3f);
  }

  TEST(
    KeptPaths,
    TargetModesPinTheEndsAndLimitTheGrade
  )
  {
    KeptPath path = NewKeptPath(KeptPathMode::Ramp, false, "p1");
    AddKeptPathPoint(path, 10.0f, 10.0f, Ground);
    AddKeptPathPoint(path, 110.0f, 10.0f, Ground);
    ASSERT_TRUE(path.points.front().abs);
    ASSERT_TRUE(path.points.back().abs);
    path.points.back().h = 60.0f; // 40 up over 100: 0.4 a unit
    path.limitGrade = true;
    path.grade = 0.2f;
    const KeptPathReport report = ReportKeptPath(path, Ground, 0.0f);
    EXPECT_NEAR(report.ys.front(), 20.0f, 0.3f);
    EXPECT_NEAR(report.ys.back(), 60.0f, 0.3f);
    // The ends are pinned, so the grade limit can't hold all along: the steepest part is reported.
    EXPECT_GT(report.max, 0.2f);
  }

  TEST(
    KeptPaths,
    CarveDigsAndApplyingAgainReplaces
  )
  {
    std::vector<std::uint16_t> words = Flat(20.0f);
    KeptPath path = NewKeptPath(KeptPathMode::Carve, false, "p1");
    AddKeptPathPoint(path, 20.0f, 64.0f, Ground);
    AddKeptPathPoint(path, 108.0f, 64.0f, Ground);
    for (KeptPathPoint& p : path.points) {
      p.h = -5.0f;
    }
    KeptPathGround ground;
    ground.words = words.data();
    ground.width = kSide;
    ground.height = kSide;
    const auto built = BuildKeptPath(path, ground, nullptr, false);
    ASSERT_TRUE(built) << built.error();
    const KeptPathPlan& plan = *built;
    EXPECT_LT(plan.lowest, -4.0f);
    EXPECT_GT(plan.changed, 100U);
    // Written in, kept as the result; the same build on top of it with the result taken off gives the same words.
    const int w = plan.x1 - plan.x0 + 1;
    for (int z = plan.z0; z <= plan.z1; ++z) {
      for (int x = plan.x0; x <= plan.x1; ++x) {
        words[static_cast<std::size_t>(z) * kSide + x] =
          plan.words[static_cast<std::size_t>(z - plan.z0) * w + (x - plan.x0)];
      }
    }
    KeptPathResult result;
    result.x0 = plan.x0;
    result.z0 = plan.z0;
    result.x1 = plan.x1;
    result.z1 = plan.z1;
    result.heightDelta = plan.delta;
    const auto again = BuildKeptPath(path, ground, &result, false);
    ASSERT_TRUE(again) << again.error();
    EXPECT_EQ(again->words, plan.words);
  }

  TEST(
    KeptPaths,
    FileTextReadsBack
  )
  {
    KeptPathSet set;
    KeptPath path = NewKeptPath(KeptPathMode::River, true, set.TakeId());
    AddKeptPathPoint(path, 1.0f, 2.0f, Ground);
    AddKeptPathPoint(path, 30.0f, 40.0f, Ground);
    path.points[1].hasHo = true;
    path.points[1].ho[0] = 3.0f;
    path.strata[0].layer = 3;
    path.props.on = true;
    path.props.what = "/env/evergreen/props/rocks/rock01_prop.bp";
    path.skeleton = true;
    set.paths.push_back(path);
    const auto read = ReadKeptPaths(KeptPathsText(set));
    ASSERT_TRUE(read) << read.error();
    const KeptPathSet& back = *read;
    ASSERT_EQ(back.paths.size(), 1U);
    EXPECT_EQ(KeptPathsText(back), KeptPathsText(set));
    EXPECT_TRUE(back.paths[0].bezier);
    EXPECT_EQ(back.paths[0].mode, KeptPathMode::River);
    EXPECT_TRUE(back.paths[0].skeleton);
  }

  TEST(
    KeptPaths,
    ProfileIsMonotoneBetweenItsPoints
  )
  {
    KeptPathProfile profile;
    profile.points = {{0.0f, 1.0f}, {0.5f, 0.6f}, {1.0f, 0.0f}};
    float last = 2.0f;
    for (int i = 0; i <= 20; ++i) {
      const float v = EvalKeptPathProfile(profile, static_cast<float>(i) / 20.0f);
      EXPECT_LE(v, last + 1e-5f);
      last = v;
    }
    EXPECT_NEAR(EvalKeptPathProfile(profile, 0.5f), 0.6f, 1e-5f);
  }

  TEST(
    Skeleton,
    RingAndHubConnectTheStarts
  )
  {
    const std::vector<SkeletonStart> starts = SkeletonStarts(
      {{"ARMY_2", "Blank Marker", 100, 20},
       {"ARMY_1", "Blank Marker", 20, 20},
       {"MASS_1", "Mass", 1, 1},
       {"ARMY_3", "Blank Marker", 60, 100}}
    );
    ASSERT_EQ(starts.size(), 3U);
    EXPECT_EQ(starts[0].name, "ARMY_1");
    SkeletonNode hub;
    EXPECT_EQ(SkeletonConnections(starts, SkeletonTopology::Ring, hub).size(), 3U);
    EXPECT_EQ(SkeletonConnections(starts, SkeletonTopology::Both, hub).size(), 6U);
    SkeletonSettings settings;
    settings.style = SkeletonStyle::Ridge;
    PadSettings pads;
    KeptPathSet ids;
    const std::vector<Pad> made = SkeletonPads(starts, settings, pads, Ground);
    EXPECT_EQ(made.size(), 3U);
    const std::vector<KeptPath> paths = SkeletonPaths(starts, settings, pads, made, Ground, 10.0f, ids);
    // Ridge: a lane and two ridges per connection.
    EXPECT_EQ(paths.size(), 9U);
    for (const KeptPath& p : paths) {
      EXPECT_TRUE(p.skeleton);
      EXPECT_GE(p.points.size(), 2U);
    }
    settings.style = SkeletonStyle::Islands;
    EXPECT_EQ(SkeletonPaths(starts, settings, pads, made, Ground, 10.0f, ids).size(), 6U); // 3 moats, 3 causeways
  }

  TEST(
    DetailPass,
    ClassesFollowWhatExistsAndCountsScale
  )
  {
    const std::vector<std::string> blueprints = {
      "/env/evergreen/props/rocks/fieldstone01_prop.bp", "/env/evergreen/props/rocks/rock03_prop.bp"
    };
    const std::vector<DetailClass> classes =
      DetailClasses("evergreen", [&blueprints](const std::string& group, const std::string& name) {
      return FindEnvironmentProp(blueprints, group, name);
    }, [](const std::string& path) {
      return path.contains("eg_cliff01");
    });
    // small and stones (fieldstone01), big (rock03), cliff (one decal); crack and ground have nothing.
    ASSERT_EQ(classes.size(), 4U);
    EXPECT_EQ(DetailCount(classes[0], 1024.0 * 1024.0, 1.0f), 10276);
    EXPECT_EQ(
      GuessDetailEnvironment({"/env/Desert/Layers/des_sand_albedo.dds", "/env/desert/x.dds", "/env/tundra/y.dds"}),
      "desert"
    );
  }

  TEST(
    MissionImport,
    OutlineOfAHandWrittenScript
  )
  {
    const std::string script = R"(
local ScenarioFramework = import('/lua/ScenarioFramework.lua')
local M1AI = import('/maps/x/x_m1ai.lua')
-- ScenarioInfo.MissionNumber = 9 (a comment)
function OnStart()
    IntroMission1()
end
function IntroMission1()
    ScenarioInfo.MissionNumber = 1
    M1AI.Base()
    StartMission1()
end
function StartMission1()
    ScenarioInfo.M1P1 = Objectives.Kill('primary', 'incomplete', 'Destroy the base', 'Every unit', {})
    ScenarioFramework.CreateTimerTrigger(M1Win, 300)
    ScenarioFramework.Dialogue(OpStrings.M1Intro, nil, true)
    if ScenarioInfo.Options.Difficulty >= 2 then end
end
function M1Win()
    ScenarioInfo.MissionNumber = 2
end
)";
    const MissionOutline o = ParseMissionScript(script);
    ASSERT_EQ(o.stages.size(), 2U);
    EXPECT_EQ(o.stages[0].number, 1);
    EXPECT_EQ(o.stages[0].entry, "IntroMission1");
    ASSERT_EQ(o.objectives.size(), 1U);
    EXPECT_EQ(o.objectives[0].title, "Destroy the base");
    EXPECT_EQ(o.objectives[0].stage, 1);
    ASSERT_EQ(o.triggers.size(), 1U);
    EXPECT_EQ(o.triggers[0].callback, "M1Win");
    EXPECT_EQ(o.dialogueRefs.size(), 1U);
    EXPECT_EQ(o.helpers.size(), 1U); // M1AI.Base (an AI module)
    EXPECT_EQ(o.difficultyUses, 1);
    const std::vector<ImportedStageRows> stages = ImportedStages(o);
    EXPECT_GE(stages.size(), 2U);
  }

  TEST(
    MissionImport,
    StringsFileDialogues
  )
  {
    const std::string strings = R"(
M1Intro = {
  {text = '[{i Commander}]: Move out.', vid = 'x.sfd', bank = 'A', cue = 'B', faction = 'UEF', delay = 3},
  {text = "Second line", character = 'Aide'},
}
OPERATION_NAME = 'Operation Test'
)";
    const std::vector<MissionDialogue> d = ParseMissionStrings(strings);
    ASSERT_EQ(d.size(), 2U);
    EXPECT_EQ(d[0].name, "M1Intro");
    ASSERT_EQ(d[0].lines.size(), 2U);
    EXPECT_EQ(d[0].lines[0].speaker, "Commander");
    EXPECT_EQ(d[0].lines[0].text, "Move out.");
    EXPECT_DOUBLE_EQ(d[0].lines[0].seconds, 3.0);
    EXPECT_EQ(d[1].lines[0].text, "Operation Test");
  }

  TEST(
    UnitIcon,
    CompareAndToneFit
  )
  {
    constexpr int side = 16;
    std::vector<std::uint8_t> a(side * side * 4, 0);
    std::vector<std::uint8_t> b(side * side * 4, 0);
    for (int y = 4; y < 12; ++y) {
      for (int x = 4; x < 12; ++x) {
        std::uint8_t* p = a.data() + (y * side + x) * 4;
        p[0] = 100;
        p[1] = 100;
        p[2] = 100;
        p[3] = 255;
        std::uint8_t* q = b.data() + (y * side + x) * 4;
        q[0] = 150;
        q[1] = 120;
        q[2] = 100;
        q[3] = 255;
      }
    }
    const IconMetrics m = CompareIcons(a.data(), b.data(), side);
    EXPECT_FLOAT_EQ(m.iou, 1.0f);
    EXPECT_GT(m.colour, 0.0f);
    IconToneFit fit;
    for (int i = 0; i < 5; ++i) {
      fit.Add("UEF", a.data(), b.data(), side);
    }
    float gains[3] = {0, 0, 0};
    ASSERT_TRUE(fit.Gains("UEF", gains));
    EXPECT_NEAR(gains[0], 1.5f, 1e-4f);
    EXPECT_EQ(IconFactionOf("xsl0101"), "Seraphim");
  }
} // namespace faf::editor
