#include "editor/tools/EdTerrainChecks.h"

#include <gtest/gtest.h>

namespace faf::editor
{
  namespace
  {
    field::Grid Flat(
      const float height = 20.0f
    )
    {
      return field::Grid(129, 129, 1.0f, 0.0f, 0.0f, height);
    }

    std::vector<CheckIssue> Of(
      const std::vector<CheckIssue>& issues,
      const std::string& marker
    )
    {
      std::vector<CheckIssue> out;
      for (const CheckIssue& issue : issues) {
        if (issue.marker == marker) {
          out.push_back(issue);
        }
      }
      return out;
    }
  } // namespace

  TEST(
    TerrainChecks,
    FlatGroundHasNothingToReport
  )
  {
    const std::vector<CheckIssue> issues =
      CheckTerrainGround(Flat(), {{"ARMY_1", 30.0f, 30.0f}}, {{"Mass 01", 60.5f, 60.5f}}, TerrainCheckSettings{});
    EXPECT_TRUE(issues.empty());
  }

  TEST(
    TerrainChecks,
    SteepBaseAreaAndUnevenResourceGroundAreWarnings
  )
  {
    field::Grid h = Flat();
    // Ridges of 2 units every other sample around ARMY_1: the land rule (0.75) blocks all of it.
    for (int z = 24; z <= 36; ++z) {
      for (int x = 24; x <= 36; ++x) {
        h.At(x, z) += (x % 2) * 2.0f;
      }
    }
    // A step of 3 under Mass 01; Mass 02 sits on flat ground.
    for (int z = 0; z < 129; ++z) {
      for (int x = 61; x < 129; ++x) {
        h.At(x, z) += x < 90 ? 3.0f : 0.0f;
      }
    }
    const std::vector<CheckIssue> issues = CheckTerrainGround(
      h,
      {{"ARMY_1", 30.0f, 30.0f}, {"ARMY_2", 100.0f, 100.0f}},
      {{"Mass 01", 60.5f, 60.5f}, {"Mass 02", 110.5f, 20.5f}},
      TerrainCheckSettings{}
    );
    const auto army1 = Of(issues, "ARMY_1");
    ASSERT_EQ(army1.size(), 1U);
    EXPECT_EQ(army1[0].level, CheckIssue::Level::Warning);
    EXPECT_NE(army1[0].text.find("too steep for land units"), std::string::npos) << army1[0].text;
    EXPECT_TRUE(Of(issues, "ARMY_2").empty());
    const auto mass1 = Of(issues, "Mass 01");
    ASSERT_EQ(mass1.size(), 1U);
    EXPECT_NE(mass1[0].text.find("varies by 3.00"), std::string::npos) << mass1[0].text;
    EXPECT_TRUE(Of(issues, "Mass 02").empty());
  }

  TEST(
    TerrainChecks,
    RouteAroundAWallIsALongDetour
  )
  {
    const std::vector<TerrainCheckPoint> starts = {{"ARMY_1", 54.0f, 64.0f}, {"ARMY_2", 74.0f, 64.0f}};
    // Open ground: a note with the straight route.
    std::vector<CheckIssue> issues = CheckTerrainRoutes(Flat(), -1e9f, starts, TerrainCheckSettings{});
    ASSERT_EQ(issues.size(), 1U);
    EXPECT_EQ(issues[0].marker, "ARMY_2");
    EXPECT_EQ(issues[0].level, CheckIssue::Level::Note);
    EXPECT_NE(issues[0].text.find("route from ARMY_1 by land: 20 units"), std::string::npos) << issues[0].text;
    // A wall between them with a gap at the map's edge: the route goes round it.
    field::Grid wall = Flat();
    for (int z = 8; z < 129; ++z) {
      for (int x = 62; x <= 66; ++x) {
        wall.At(x, z) = 80.0f;
      }
    }
    issues = CheckTerrainRoutes(wall, -1e9f, starts, TerrainCheckSettings{});
    ASSERT_EQ(issues.size(), 1U);
    EXPECT_EQ(issues[0].level, CheckIssue::Level::Warning);
    EXPECT_NE(issues[0].text.find("a long detour"), std::string::npos) << issues[0].text;
    // Closed: separate ground is the pathing check's to report, not a route.
    for (int x = 62; x <= 66; ++x) {
      for (int z = 0; z < 8; ++z) {
        wall.At(x, z) = 80.0f;
      }
    }
    EXPECT_TRUE(CheckTerrainRoutes(wall, -1e9f, starts, TerrainCheckSettings{}).empty());
    // Under deep water nothing is land.
    EXPECT_TRUE(CheckTerrainRoutes(Flat(0.0f), 10.0f, starts, TerrainCheckSettings{}).empty());
  }
} // namespace faf::editor
