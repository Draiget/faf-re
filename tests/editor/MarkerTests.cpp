// The map editor's markers (src/editor/tools/EdMarkers.cpp): new names skip the ones taken, a new marker
// carries its type's properties in the saves' order, and positions, colours and path links read back.

#include "editor/tools/EdMarkers.h"

#include <gtest/gtest.h>

namespace
{
  using faf::editor::SaveEntry;

  TEST(Markers, NamesSkipTheOnesTaken)
  {
    const faf::editor::MarkerType* const mass = faf::editor::FindMarkerType("Mass");
    const faf::editor::MarkerType* const start = faf::editor::FindMarkerType("Blank Marker");
    ASSERT_NE(mass, nullptr);
    ASSERT_NE(start, nullptr);
    std::vector<SaveEntry> markers = {{"Mass 00", {}}, {"Mass 01", {}}, {"ARMY_1", {}}, {"ARMY_3", {}}};
    EXPECT_EQ(faf::editor::NextMarkerName(markers, *mass), "Mass 02");
    EXPECT_EQ(faf::editor::NextMarkerName(markers, *start), "ARMY_2");
  }

  TEST(Markers, ANewMarkerReadsBack)
  {
    const faf::editor::MarkerType* const node = faf::editor::FindMarkerType("Land Path Node");
    ASSERT_NE(node, nullptr);
    SaveEntry marker = faf::editor::NewMarker(*node, "LandPN00", 10.5f, 20.0f, 30.5f);
    float x = 0.0f, y = 0.0f, z = 0.0f;
    ASSERT_TRUE(faf::editor::MarkerPosition(marker, x, y, z));
    EXPECT_FLOAT_EQ(x, 10.5f);
    EXPECT_FLOAT_EQ(z, 30.5f);
    EXPECT_EQ(faf::editor::MarkerTypeOf(marker), "Land Path Node");
    EXPECT_EQ(faf::editor::MarkerColor(marker), 0xFF00FF00u);
    EXPECT_EQ(marker.Get("graph"), "STRING( 'DefaultLand' )");
    // The saves' order: the type's own properties, then color, type, prop, orientation, position.
    EXPECT_EQ(marker.properties.front().first, "hint");
    EXPECT_EQ(marker.properties.back().first, "position");
    marker.Set("adjacentTo", faf::editor::StringValue("LandPN01 LandPN02"));
    const std::vector<std::string> links = faf::editor::MarkerLinks(marker);
    ASSERT_EQ(links.size(), 2u);
    EXPECT_EQ(links[1], "LandPN02");
  }
} // namespace
