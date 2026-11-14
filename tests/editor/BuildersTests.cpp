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
    std::vector<MissionBuilder> builders;
    std::string error;
    ASSERT_TRUE(ParseBuilders(text, builders, error)) << error;
    ASSERT_EQ(builders.size(), 2U);
    EXPECT_EQ(builders[0].name, "M1_Attack");
    EXPECT_EQ(builders[0].Get("PlatoonTemplate"), "'M1_Tanks'");
    EXPECT_EQ(builders[0].Get("BuildConditions"), "{ { '/lua/editor/miscbuildconditions.lua', 'True', {} }, }");
    EXPECT_EQ(builders[1].Get("PlatoonTemplate"), "\"Air, wings\"");
    EXPECT_EQ(builders[1].Get("InstanceCount"), "2");
    builders[0].Set("Priority", "250");
    builders.push_back(NewBuilder("Third", "T", "MAIN"));
    std::vector<MissionBuilder> again;
    ASSERT_TRUE(ParseBuilders(FormatBuilders(builders), again, error)) << error;
    ASSERT_EQ(again.size(), 3U);
    EXPECT_EQ(again[0].Get("Priority"), "250");
    EXPECT_EQ(again[0].Get("BuildConditions"), builders[0].Get("BuildConditions"));
    EXPECT_EQ(again[2].Get("LocationType"), "'MAIN'");
    EXPECT_TRUE(ParseBuilders("", again, error));
    EXPECT_TRUE(again.empty());
  }
} // namespace faf::editor
