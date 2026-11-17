// Platoon builders read from and written to an army's PlatoonBuilders text.

#include "editor/tools/EdBuilders.h"

#include <gtest/gtest.h>

namespace faf::editor
{
  TEST(
    Builders,
    ReadEditWriteRead
  )
  {
    const std::string text = R"lua({
                    Builders = {
                        ['M1_Attack'] = {
                            PlatoonTemplate = 'M1_Tanks',
                            Priority = 100,
                            BuildConditions = { { '/lua/editor/miscbuildconditions.lua', 'True', {} }, },
                            PlatoonType = 'Land',
                        },
                        Second = { PlatoonTemplate = "Air, wings", InstanceCount = 2 },
                    },
                })lua";
    auto parsed = ParseBuilders(text);
    ASSERT_TRUE(parsed) << parsed.error();
    std::vector<MissionBuilder>& builders = *parsed;
    ASSERT_EQ(builders.size(), 2U);
    EXPECT_EQ(builders[0].name, "M1_Attack");
    EXPECT_EQ(builders[0].Get("PlatoonTemplate"), "'M1_Tanks'");
    EXPECT_EQ(builders[0].Get("BuildConditions"), "{ { '/lua/editor/miscbuildconditions.lua', 'True', {} }, }");
    EXPECT_EQ(builders[1].Get("PlatoonTemplate"), "\"Air, wings\"");
    EXPECT_EQ(builders[1].Get("InstanceCount"), "2");
    builders[0].Set("Priority", "250");
    builders.push_back(NewBuilder("Third", "T", "MAIN"));
    const auto reparsed = ParseBuilders(FormatBuilders(builders));
    ASSERT_TRUE(reparsed) << reparsed.error();
    const std::vector<MissionBuilder>& again = *reparsed;
    ASSERT_EQ(again.size(), 3U);
    EXPECT_EQ(again[0].Get("Priority"), "250");
    EXPECT_EQ(again[0].Get("BuildConditions"), builders[0].Get("BuildConditions"));
    EXPECT_EQ(again[2].Get("LocationType"), "'MAIN'");
    const auto none = ParseBuilders("");
    EXPECT_TRUE(none);
    EXPECT_TRUE(none->empty());
  }
} // namespace faf::editor
