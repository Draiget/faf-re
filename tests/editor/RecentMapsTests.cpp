// The map editor's recent maps (src/editor/doc/EdRecentMaps.cpp): newest first, no repeats, a limit, read back as
// written.

#include "editor/doc/EdRecentMaps.h"

#include <cstdio>
#include <filesystem>

#include <gtest/gtest.h>

namespace
{
  TEST(
    RecentMaps,
    NewestFirstWithoutRepeats
  )
  {
    std::vector<std::string> list;
    list = faf::editor::WithRecentMap(list, "/maps/a/a_scenario.lua");
    list = faf::editor::WithRecentMap(list, "/maps/b/b_scenario.lua");
    list = faf::editor::WithRecentMap(list, "/MAPS/A/a_scenario.lua");
    const std::vector<std::string> expected = {"/MAPS/A/a_scenario.lua", "/maps/b/b_scenario.lua"};
    EXPECT_EQ(list, expected);
  }

  TEST(
    RecentMaps,
    OldestDroppedPastTheLimit
  )
  {
    std::vector<std::string> list;
    for (int i = 0; i < 5; ++i) {
      list = faf::editor::WithRecentMap(list, "/maps/m" + std::to_string(i), 3);
    }
    const std::vector<std::string> expected = {"/maps/m4", "/maps/m3", "/maps/m2"};
    EXPECT_EQ(list, expected);
  }

  TEST(
    RecentMaps,
    ReadBackAsWritten
  )
  {
    const std::string file = (std::filesystem::temp_directory_path() / "faf_editor_recent_maps_test.txt").string();
    const std::vector<std::string> list = {"/maps/scmp_009/scmp_009_scenario.lua", "/maps/x y/x y_scenario.lua"};
    ASSERT_TRUE(faf::editor::WriteRecentMaps(file, list));
    EXPECT_EQ(faf::editor::ReadRecentMaps(file), list);
    (void)std::remove(file.c_str());
    EXPECT_TRUE(faf::editor::ReadRecentMaps(file).empty());
  }
} // namespace
