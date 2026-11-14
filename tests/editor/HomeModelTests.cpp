// The map editor's start screen (src/editor/ui/EdHomeModel.cpp): same-size cards filling a row, the search over the
// maps here, the vault searches it runs, how long ago a map changed, and New's five kinds.

#include "editor/ui/EdHomeModel.h"

#include <gtest/gtest.h>

using faf::editor::CardGrid;
using faf::editor::LocalMatches;
using faf::editor::MostPlayedQuery;
using faf::editor::NewKinds;
using faf::editor::TypedQuery;
using faf::editor::UploadsQuery;
using faf::editor::WhenText;

namespace
{
  TEST(
    HomeModel,
    CardsFillTheRowAtTheSameSize
  )
  {
    const auto grid = CardGrid(1000.0f, 190.0f, 14.0f, 5);
    EXPECT_EQ(grid.columns, 4) << "five of 190 and four gaps need 1006";
    EXPECT_FLOAT_EQ(grid.cardWidth * 4.0f + 14.0f * 3.0f, 1000.0f) << "the row is filled";
    EXPECT_GE(grid.cardWidth, 190.0f);
    EXPECT_EQ(CardGrid(3000.0f, 190.0f, 14.0f, 5).columns, 5) << "no more than asked";
    EXPECT_EQ(CardGrid(100.0f, 190.0f, 14.0f, 5).columns, 1) << "one, narrower, when even one doesn't fit";
    EXPECT_FLOAT_EQ(CardGrid(100.0f, 190.0f, 14.0f, 5).cardWidth, 100.0f);
    EXPECT_EQ(CardGrid(0.0f, 190.0f, 14.0f, 5).cardWidth, 0.0f);
  }

  TEST(
    HomeModel,
    SearchMatchesTitlesAndFoldersBestFirst
  )
  {
    const std::vector<std::string> titles = {"Seton's Clutch", "Setons Rework", "Dual Gap", "Open Palms"};
    const std::vector<std::string> paths = {
      "/maps/scmp_009/scmp_009_scenario.lua",
      "/maps/setons_rework/setons_rework_scenario.lua",
      "/maps/dualgap_adaptive/dualgap_adaptive_scenario.lua",
      "/maps/scmp_007/scmp_007_scenario.lua"
    };
    const auto setons = LocalMatches(titles, paths, "setons", 10);
    ASSERT_GE(setons.size(), 2u);
    EXPECT_TRUE((setons[0] == 0 || setons[0] == 1) && (setons[1] == 0 || setons[1] == 1));
    EXPECT_EQ(LocalMatches(titles, paths, "scmp_007", 10), (std::vector<int>{3})) << "by folder too";
    EXPECT_EQ(LocalMatches(titles, paths, "gap", 10).front(), 2);
    EXPECT_TRUE(LocalMatches(titles, paths, "", 10).empty());
    EXPECT_TRUE(LocalMatches(titles, paths, "zzzz", 10).empty());
    EXPECT_EQ(LocalMatches(titles, paths, "s", 1).size(), 1u) << "at most max";
  }

  TEST(
    HomeModel,
    VaultSearches
  )
  {
    const auto uploads = UploadsQuery("someone");
    EXPECT_EQ(uploads.author, "someone");
    EXPECT_EQ(uploads.sortProperty, "latestVersion.updateTime");
    EXPECT_TRUE(uploads.descending);
    EXPECT_EQ(MostPlayedQuery().sortProperty, "gamesPlayed");
    EXPECT_TRUE(MostPlayedQuery().text.empty());
    EXPECT_EQ(TypedQuery("dual gap").text, "dual gap");
  }

  TEST(
    HomeModel,
    WhenAMapChanged
  )
  {
    EXPECT_EQ(WhenText(20.0), "Just now");
    EXPECT_EQ(WhenText(61.0), "1 minute ago");
    EXPECT_EQ(WhenText(60.0 * 25.0), "25 minutes ago");
    EXPECT_EQ(WhenText(3600.0), "1 hour ago");
    EXPECT_EQ(WhenText(3600.0 * 2.5), "2 hours ago");
    EXPECT_EQ(WhenText(86400.0 * 1.5), "yesterday");
    EXPECT_EQ(WhenText(86400.0 * 3.2), "3 days ago");
    EXPECT_EQ(WhenText(86400.0 * 21.0), "3 weeks ago");
    EXPECT_EQ(WhenText(86400.0 * 120.0), "3 months ago");
    EXPECT_EQ(WhenText(86400.0 * 800.0), "2 years ago");
  }

  TEST(
    HomeModel,
    NewMakesFiveKinds
  )
  {
    ASSERT_EQ(NewKinds().size(), 5u);
    EXPECT_STREQ(NewKinds()[0].title, "Map");
    EXPECT_STREQ(NewKinds()[0].command, "file.new");
    for (const auto& kind : NewKinds()) {
      EXPECT_NE(std::string(kind.about), "");
    }
  }
} // namespace
