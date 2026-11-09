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
} // namespace
