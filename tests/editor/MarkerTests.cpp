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

  TEST(Markers, PathNodesLinkBothWaysAndUnlink)
  {
    const faf::editor::MarkerType* const land = faf::editor::FindMarkerType("Land Path Node");
    const faf::editor::MarkerType* const water = faf::editor::FindMarkerType("Water Path Node");
    const faf::editor::MarkerType* const mass = faf::editor::FindMarkerType("Mass");
    ASSERT_NE(land, nullptr);
    std::vector<SaveEntry> markers = {
      faf::editor::NewMarker(*land, "LandPN00", 10.5f, 0.0f, 10.5f),
      faf::editor::NewMarker(*land, "LandPN01", 30.5f, 0.0f, 10.5f),
      faf::editor::NewMarker(*land, "LandPN02", 50.5f, 0.0f, 10.5f),
      faf::editor::NewMarker(*water, "WaterPN00", 70.5f, 0.0f, 10.5f),
      faf::editor::NewMarker(*mass, "Mass 00", 90.5f, 0.0f, 10.5f),
    };
    EXPECT_TRUE(faf::editor::IsPathNode(markers[0]));
    EXPECT_FALSE(faf::editor::IsPathNode(markers[4]));
    EXPECT_TRUE(faf::editor::SetMarkerLink(markers, "LandPN00", "LandPN01", true));
    EXPECT_TRUE(faf::editor::SetMarkerLink(markers, "LandPN01", "LandPN02", true));
    EXPECT_FALSE(faf::editor::SetMarkerLink(markers, "LandPN01", "LandPN00", true)); // already linked
    EXPECT_EQ(markers[1].Get("adjacentTo"), "STRING( 'LandPN00 LandPN02' )");
    EXPECT_EQ(markers[0].Get("adjacentTo"), "STRING( 'LandPN01' )");
    EXPECT_TRUE(faf::editor::MarkersLinked(markers, "LandPN02", "LandPN01"));
    // Different graphs and non-nodes don't link.
    EXPECT_FALSE(faf::editor::SetMarkerLink(markers, "LandPN00", "WaterPN00", true));
    EXPECT_FALSE(faf::editor::SetMarkerLink(markers, "Mass 00", "LandPN00", true));
    // A one-sided link (as some maps have) still counts and unlinks both ways.
    markers[2].Set("adjacentTo", faf::editor::StringValue("LandPN01 LandPN00"));
    EXPECT_TRUE(faf::editor::MarkersLinked(markers, "LandPN00", "LandPN02"));
    EXPECT_TRUE(faf::editor::SetMarkerLink(markers, "LandPN00", "LandPN02", false));
    EXPECT_FALSE(faf::editor::MarkersLinked(markers, "LandPN00", "LandPN02"));
    // Deleting LandPN01 drops the links that name it.
    EXPECT_EQ(faf::editor::RemoveLinksTo(markers, "LandPN01"), 2);
    EXPECT_EQ(markers[0].Get("adjacentTo"), "STRING( '' )");
    EXPECT_TRUE(faf::editor::MarkerLinks(markers[2]).empty());
  }

  TEST(Markers, GroupsForTheTree)
  {
    using faf::editor::MarkerGroup;
    const auto of = [](const char* const type) {
      return faf::editor::MarkerGroupOf(faf::editor::NewMarker(*faf::editor::FindMarkerType(type), "m", 0.0f, 0.0f, 0.0f));
    };
    EXPECT_EQ(of("Blank Marker"), MarkerGroup::Starts);
    EXPECT_EQ(of("Mass"), MarkerGroup::Resources);
    EXPECT_EQ(of("Hydrocarbon"), MarkerGroup::Resources);
    EXPECT_EQ(of("Rally Point"), MarkerGroup::Ai);
    EXPECT_EQ(of("Naval Link"), MarkerGroup::Ai);
    EXPECT_EQ(of("Air Path Node"), MarkerGroup::PathNodes);
    EXPECT_EQ(of("Camera Info"), MarkerGroup::Other);
    // A type the palette doesn't know (a mod's) goes to Other.
    SaveEntry odd{"x", {{"type", faf::editor::StringValue("Weather Generator")}}};
    EXPECT_EQ(faf::editor::MarkerGroupOf(odd), MarkerGroup::Other);
  }

  TEST(Markers, NearestOfATypeWithinReach)
  {
    const faf::editor::MarkerType* const land = faf::editor::FindMarkerType("Land Path Node");
    const faf::editor::MarkerType* const mass = faf::editor::FindMarkerType("Mass");
    const std::vector<SaveEntry> markers = {
      faf::editor::NewMarker(*mass, "Mass 00", 10.5f, 0.0f, 10.5f),
      faf::editor::NewMarker(*land, "LandPN00", 11.5f, 0.0f, 10.5f),
    };
    EXPECT_EQ(faf::editor::MarkerNear(markers, "Land Path Node", 10.5f, 10.5f, 1.5f), 1);
    EXPECT_EQ(faf::editor::MarkerNear(markers, "Mass", 11.5f, 10.5f, 1.5f), 0);
    EXPECT_EQ(faf::editor::MarkerNear(markers, "Land Path Node", 20.5f, 10.5f, 1.5f), -1);
  }
} // namespace
