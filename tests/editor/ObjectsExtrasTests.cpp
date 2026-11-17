// Objects extras: per-start statistics, footprint snapping and fit, scatter by area, ground path graphs, chain checks.

#include "editor/doc/EdSaveFile.h"
#include "editor/tools/EdChecks.h"
#include "editor/tools/EdMapStats.h"
#include "editor/tools/EdMarkers.h"
#include "editor/tools/EdScatter.h"

#include <gtest/gtest.h>

#include <cmath>

namespace faf::editor
{
  TEST(
    MapStats,
    NearestStartTakesEach
  )
  {
    std::vector<StatStart> starts(2);
    starts[0].name = "ARMY_1";
    starts[0].x = 10.0f;
    starts[0].z = 10.0f;
    starts[1].name = "ARMY_2";
    starts[1].x = 100.0f;
    starts[1].z = 100.0f;
    const std::vector<StatThing> things = {
      {StatThing::Kind::Mass, 12.0f, 12.0f, 0.0, 0.0},
      {StatThing::Kind::Mass, 15.0f, 8.0f, 0.0, 0.0},
      {StatThing::Kind::Mass, 95.0f, 99.0f, 0.0, 0.0},
      {StatThing::Kind::Hydro, 98.0f, 98.0f, 0.0, 0.0},
      {StatThing::Kind::Prop, 20.0f, 20.0f, 30.0, 5.0},
      {StatThing::Kind::Prop, 90.0f, 90.0f, 12.5, 0.0},
    };
    const std::vector<StatStart> out = PerStart(starts, things);
    EXPECT_EQ(out[0].mass, 2);
    EXPECT_EQ(out[1].mass, 1);
    EXPECT_EQ(out[1].hydro, 1);
    EXPECT_DOUBLE_EQ(out[0].reclaimMass, 30.0);
    EXPECT_DOUBLE_EQ(out[1].reclaimMass, 12.5);
    const StatSpread spread = SpreadOf(out);
    EXPECT_EQ(spread.mass, 1);
    EXPECT_EQ(spread.hydro, 1);
    EXPECT_DOUBLE_EQ(spread.reclaimMass, 17.5);
  }

  TEST(
    UnitFit,
    FootprintSnapAndReasons
  )
  {
    EXPECT_FLOAT_EQ(SnapFootprint(10.3f, 1), 10.5f);
    EXPECT_FLOAT_EQ(SnapFootprint(10.3f, 3), 10.5f);
    EXPECT_FLOAT_EQ(SnapFootprint(10.3f, 2), 10.0f);
    EXPECT_FLOAT_EQ(SnapFootprint(10.7f, 4), 11.0f);
    FitFacts facts;
    EXPECT_TRUE(FitProblem(facts).empty());
    facts.structure = true;
    facts.maxVariation = 0.5f;
    facts.groundVaries = 0.9f;
    EXPECT_NE(FitProblem(facts).find("too steep"), std::string::npos);
    facts.waterDepth = 2.0f;
    EXPECT_NE(FitProblem(facts).find("water"), std::string::npos);
    facts.outsidePlayable = true;
    EXPECT_EQ(FitProblem(facts), "outside the playable area");
  }

  TEST(
    AreaScatter,
    DensityAndSpacing
  )
  {
    // A circle of radius 10 (314 square units) at 2 per 100: 6 wanted.
    const auto points = AreaScatter(0.0f, 0.0f, 10.0f, 2.0f, 2.0f, {}, 7U, 50);
    EXPECT_EQ(points.size(), 6U);
    for (std::size_t i = 0; i < points.size(); ++i) {
      EXPECT_LE(std::hypot(points[i].first, points[i].second), 10.0f);
      for (std::size_t j = 0; j < i; ++j) {
        EXPECT_GE(std::hypot(points[i].first - points[j].first, points[i].second - points[j].second), 2.0f);
      }
    }
    // Already full: nothing new.
    EXPECT_TRUE(AreaScatter(0.0f, 0.0f, 10.0f, 2.0f, 2.0f, points, 9U, 50).empty());
    // The same seed, the same points.
    EXPECT_EQ(AreaScatter(0.0f, 0.0f, 10.0f, 2.0f, 2.0f, {}, 7U, 50), points);
  }

  TEST(
    PathGraph,
    NodesOnTheGroundLinkedWhereReachable
  )
  {
    // A 4 x 4 grid over 0..64; the right half is water for a land unit, so its nodes aren't there.
    const auto grid = PathNodeGrid({}, "Land Path Node", 4, 0.0f, 0.0f, 64.0f, 64.0f, [](float, float) {
      return 10.0f;
    }, [](const float x, float) {
      return x < 32.0f;
    }, [](float, float, float, float) {
      return true;
    });
    EXPECT_EQ(grid.size(), 8U);
    for (const SaveEntry& node : grid) {
      EXPECT_EQ(MarkerTypeOf(node), "Land Path Node");
      float x = 0.0f, y = 0.0f, z = 0.0f;
      ASSERT_TRUE(MarkerPosition(node, x, y, z));
      EXPECT_LT(x, 32.0f);
    }
    EXPECT_FALSE(grid.front().Get("adjacentTo").empty());
  }

  TEST(
    ChainChecks,
    ShortAndRepeated
  )
  {
    std::vector<SaveEntry> markers = {
      NewMarker(*FindMarkerType("Blank Marker"), "A", 1.0f, 0.0f, 1.0f),
      NewMarker(*FindMarkerType("Blank Marker"), "B", 2.0f, 0.0f, 2.0f)
    };
    std::vector<MarkerChain> chains = {{"Short", {"A"}}, {"Twice", {"A", "B", "A"}}};
    MapBasicsInput input;
    input.markers = &markers;
    input.chains = &chains;
    input.name = "x";
    input.description = "x";
    const std::vector<CheckIssue> issues = CheckMapBasics(input);
    bool shortFound = false;
    bool twiceFound = false;
    for (const CheckIssue& issue : issues) {
      shortFound = shortFound || (issue.marker == "Short" && issue.text.contains("needs two"));
      twiceFound = twiceFound || (issue.marker == "Twice" && issue.text.contains("more than once"));
    }
    EXPECT_TRUE(shortFound);
    EXPECT_TRUE(twiceFound);
  }
} // namespace faf::editor
