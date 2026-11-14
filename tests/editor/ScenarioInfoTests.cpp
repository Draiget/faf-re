#include "editor/doc/EdScenarioInfo.h"

#include <gtest/gtest.h>

namespace faf::editor
{
  namespace
  {
    const char* const kScenario = "version = 3 -- the file's own version\r\n"
                                  "ScenarioInfo = {\r\n"
                                  "    name = '<LOC SCMP_009_name>Seton\\'s Clutch',\r\n"
                                  "    description = \"Dozens of battles\",\r\n"
                                  "    -- name = 'not this one'\r\n"
                                  "    type = 'skirmish',\r\n"
                                  "    map_version = 2,\r\n"
                                  "    Configurations = {\r\n"
                                  "        ['standard'] = { teams = { { name = 'FFA', armies = {'ARMY_1'} } } },\r\n"
                                  "    },\r\n"
                                  "}\r\n";
  }

  TEST(
    ScenarioInfo,
    FieldsReadAndWriteInPlace
  )
  {
    std::string v;
    ASSERT_TRUE(ReadScenarioField(kScenario, "name", v));
    EXPECT_EQ(v, "<LOC SCMP_009_name>Seton's Clutch");
    EXPECT_EQ(WithoutLoc(v), "Seton's Clutch");
    ASSERT_TRUE(ReadScenarioField(kScenario, "map_version", v));
    EXPECT_EQ(v, "2");
    EXPECT_FALSE(ReadScenarioField(kScenario, "norushradius", v));
    EXPECT_FALSE(ReadScenarioField(kScenario, "version_x", v));
    // Written in place: the rest as it was.
    std::string s = WithScenarioField(kScenario, "name", "Seton's \"Big\" Clutch", true);
    ASSERT_TRUE(ReadScenarioField(s, "name", v));
    EXPECT_EQ(v, "Seton's \"Big\" Clutch");
    EXPECT_NE(s.find("name = \"Seton's \\\"Big\\\" Clutch\",\r\n"), std::string::npos);
    EXPECT_NE(s.find("{ name = 'FFA'"), std::string::npos) << "the team's name untouched";
    EXPECT_NE(s.find("-- name = 'not this one'"), std::string::npos);
    s = WithScenarioField(s, "map_version", "7", false);
    ASSERT_TRUE(ReadScenarioField(s, "map_version", v));
    EXPECT_EQ(v, "7");
    EXPECT_EQ(WithScenarioField(s, "map_version", "7; os.exit()", false), s) << "a number only";
    // A field the file hasn't: added inside ScenarioInfo.
    s = WithScenarioField(s, "norushradius", "75", false);
    ASSERT_TRUE(ReadScenarioField(s, "norushradius", v));
    EXPECT_EQ(v, "75");
    EXPECT_NE(s.find("ScenarioInfo = {\r\n    norushradius = 75,\r\n"), std::string::npos);
    EXPECT_EQ(ReadScenarioField(s, "version", v) && v == "3", true) << "the file's own version, a separate key";
    EXPECT_EQ(ScenarioFields().size(), 5U);
  }
} // namespace faf::editor
