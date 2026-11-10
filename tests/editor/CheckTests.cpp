// The map editor's Check (src/editor/tools/EdChecks.cpp): start positions and resources off the playable area, under
// water, without a symmetric partner, or overlapping.

#include "editor/tools/EdChecks.h"
#include "editor/tools/EdMarkers.h"

#include <gtest/gtest.h>

namespace
{
  using faf::editor::CheckIssue;
  using faf::editor::SaveEntry;

  float Flat(const void*, float, float)
  {
    return 10.0f;
  }

  SaveEntry Marker(const char* const type, const char* const name, const float x, const float z)
  {
    return faf::editor::NewMarker(*faf::editor::FindMarkerType(type), name, x, 10.0f, z);
  }

  std::size_t Count(const std::vector<CheckIssue>& issues, const std::string& marker, const std::string& words)
  {
    std::size_t n = 0;
    for (const CheckIssue& issue : issues) {
      n += issue.marker == marker && issue.text.find(words) != std::string::npos ? 1 : 0;
    }
    return n;
  }

  TEST(Check, AMirroredMapWithEverythingInPlaceIsClean)
  {
    // 257 samples, mirrored left-right: each marker has its partner at 256 - x.
    const std::vector<SaveEntry> markers = {Marker("Blank Marker", "ARMY_1", 40.5f, 100.5f), Marker("Blank Marker", "ARMY_2", 215.5f, 100.5f),
                                            Marker("Mass", "Mass 00", 60.5f, 120.5f), Marker("Mass", "Mass 01", 195.5f, 120.5f)};
    faf::editor::MarkerCheckInput input;
    input.markers = &markers;
    input.symmetry = faf::editor::Symmetry::LeftRight;
    input.width = 257;
    input.height = 257;
    input.groundAt = &Flat;
    input.water = true;
    input.waterLevel = 5.0f;
    EXPECT_TRUE(faf::editor::CheckMarkers(input).empty());
  }

  TEST(Check, LuaErrorsSplitIntoLineAndMessage)
  {
    int line = 0;
    std::string message;
    ASSERT_TRUE(faf::editor::ParseLuaError("[string \"seton_script.lua\"]:12: '=' expected near 'end'", line, message));
    EXPECT_EQ(line, 12);
    EXPECT_EQ(message, "'=' expected near 'end'");
    ASSERT_TRUE(faf::editor::ParseLuaError("/maps/x/x_save.lua:3: unexpected symbol near ':'", line, message));
    EXPECT_EQ(line, 3);
    EXPECT_EQ(message, "unexpected symbol near ':'");
    // As this engine's Lua writes them.
    ASSERT_TRUE(faf::editor::ParseLuaError("SCMP_009_script.lua(10): <name> or `...' expected near `<eof>'", line, message));
    EXPECT_EQ(line, 10);
    EXPECT_EQ(message, "<name> or `...' expected near `<eof>'");
    EXPECT_FALSE(faf::editor::ParseLuaError("not enough memory", line, message));
  }

  TEST(Check, FindsEachKindOfProblem)
  {
    const std::vector<SaveEntry> markers = {
      Marker("Blank Marker", "ARMY_1", 40.5f, 100.5f),  // no partner
      Marker("Mass", "Mass 00", 60.5f, 120.5f),         // overlaps Mass 01
      Marker("Mass", "Mass 01", 61.5f, 121.5f),
      Marker("Hydrocarbon", "Hydro 00", 10.5f, 10.5f),  // outside the playable area
    };
    faf::editor::MarkerCheckInput input;
    input.markers = &markers;
    input.playable = std::array<int, 4>{20, 20, 236, 236};
    input.symmetry = faf::editor::Symmetry::LeftRight;
    input.width = 257;
    input.height = 257;
    input.groundAt = &Flat;
    input.water = true;
    input.waterLevel = 12.0f; // above the flat ground: everything is under water
    const std::vector<CheckIssue> issues = faf::editor::CheckMarkers(input);
    EXPECT_EQ(Count(issues, "ARMY_1", "no partner"), 1u);
    EXPECT_EQ(Count(issues, "Mass 00", "overlaps Mass 01"), 1u);
    EXPECT_EQ(Count(issues, "Hydro 00", "outside the playable area"), 1u);
    // Under water: a warning for the start, a note for the resources.
    bool startWarned = false, massNoted = false;
    for (const CheckIssue& issue : issues) {
      startWarned = startWarned || (issue.marker == "ARMY_1" && issue.text.find("under water") != std::string::npos && issue.level == CheckIssue::Level::Warning);
      massNoted = massNoted || (issue.marker == "Mass 00" && issue.text.find("under water") != std::string::npos && issue.level == CheckIssue::Level::Note);
    }
    EXPECT_TRUE(startWarned);
    EXPECT_TRUE(massNoted);
  }
  TEST(Checks, PropsWithoutTheirSymmetricPartner)
  {
    using faf::editor::PropPoint;
    // A 257-sample map under a left-right mirror: x and 256 - x.
    std::vector<PropPoint> props = {
      {"/env/rock01_prop.bp", 40.0f, 100.0f, 20.0f},  {"/env/rock01_prop.bp", 216.5f, 100.0f, 20.0f}, // a pair, 0.5 apart: matched
      {"/env/tree01_prop.bp", 60.0f, 50.0f, 0.0f},    {"/env/tree01_prop.bp", 196.0f, 50.0f, 0.0f},    // a pair
      {"/env/rock01_prop.bp", 10.0f, 10.0f, 30.0f},                                                    // alone
      {"/env/tree01_prop.bp", 246.0f, 10.0f, 0.0f},                                                    // a rock's place, another blueprint
    };
    const std::vector<faf::editor::CheckIssue> issues =
      faf::editor::CheckPropSymmetry(props, faf::editor::Symmetry::LeftRight, 0, 257, 257);
    ASSERT_EQ(issues.size(), 3U); // the summary and the two unmatched
    EXPECT_EQ(issues[0].level, faf::editor::CheckIssue::Level::Warning);
    EXPECT_NE(issues[0].text.find("2 of 6 props"), std::string::npos);
    EXPECT_NE(issues[0].text.find("30 of 70 reclaim mass"), std::string::npos);
    EXPECT_EQ(issues[1].marker, "Prop rock01_prop.bp");
    EXPECT_FLOAT_EQ(issues[1].x, 10.0f);
    // No symmetry, or every prop matched: nothing.
    EXPECT_TRUE(faf::editor::CheckPropSymmetry(props, faf::editor::Symmetry::None, 0, 257, 257).empty());
    props.resize(4);
    EXPECT_TRUE(faf::editor::CheckPropSymmetry(props, faf::editor::Symmetry::LeftRight, 0, 257, 257).empty());
  }
} // namespace
