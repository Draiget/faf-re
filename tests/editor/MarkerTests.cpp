// The map editor's markers (src/editor/tools/EdMarkers.cpp): new names skip the ones taken, a new marker
// carries its type's properties in the saves' order, and positions, colours and path links read back.

#include "editor/tools/EdMarkers.h"
#include "editor/tools/EdPickFilter.h"

#include <algorithm>

#include <gtest/gtest.h>

namespace
{
  using faf::editor::SaveEntry;

  TEST(
    Markers,
    NamesSkipTheOnesTaken
  )
  {
    const faf::editor::MarkerType* const mass = faf::editor::FindMarkerType("Mass");
    const faf::editor::MarkerType* const start = faf::editor::FindMarkerType("Blank Marker");
    ASSERT_NE(mass, nullptr);
    ASSERT_NE(start, nullptr);
    std::vector<SaveEntry> markers = {{"Mass 00", {}}, {"Mass 01", {}}, {"ARMY_1", {}}, {"ARMY_3", {}}};
    EXPECT_EQ(faf::editor::NextMarkerName(markers, *mass), "Mass 02");
    EXPECT_EQ(faf::editor::NextMarkerName(markers, *start), "ARMY_2");
  }

  TEST(
    Markers,
    ANewMarkerReadsBack
  )
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

  TEST(
    Markers,
    PathNodesLinkBothWaysAndUnlink
  )
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

  TEST(
    Markers,
    GroupsForTheTree
  )
  {
    using faf::editor::MarkerGroup;
    const auto of = [](const char* const type) {
      return faf::editor::MarkerGroupOf(
        faf::editor::NewMarker(*faf::editor::FindMarkerType(type), "m", 0.0f, 0.0f, 0.0f)
      );
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

  TEST(
    Markers,
    PickFilterSeparatesPathNodesFromOtherMarkers
  )
  {
    using faf::editor::MarkerGroup;
    faf::editor::PickFilter filter;
    EXPECT_TRUE(filter.All()) << "everything pickable at first";
    filter.markers = false;
    EXPECT_FALSE(filter.Marker(MarkerGroup::Resources));
    EXPECT_FALSE(filter.Marker(MarkerGroup::Starts));
    EXPECT_TRUE(filter.Marker(MarkerGroup::PathNodes)) << "path nodes are their own kind";
    filter.markers = true;
    filter.pathNodes = false;
    EXPECT_FALSE(filter.Marker(MarkerGroup::PathNodes));
    EXPECT_TRUE(filter.Marker(MarkerGroup::Ai));
    EXPECT_FALSE(filter.All());
  }

  TEST(
    Markers,
    NearestOfATypeWithinReach
  )
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
  TEST(
    Markers,
    AirNodeGridAsFafmeLaysIt
  )
  {
    // FAForeverMapEditor's 10 km preset: 16 x 16 nodes over a 512 map, 32 apart from 16.5, 3 to 8 links each.
    const std::vector<SaveEntry> existing = {{"AirPN00", {}}, {"Mass 01", {}}};
    const std::vector<SaveEntry> grid =
      faf::editor::AirNodeGrid(existing, 16, 0.0f, 0.0f, 512.0f, 512.0f, [](float, float) {
      return 20.0f;
    });
    ASSERT_EQ(grid.size(), 256U);
    float x = 0.0f, y = 0.0f, z = 0.0f;
    ASSERT_TRUE(faf::editor::MarkerPosition(grid[0], x, y, z));
    EXPECT_FLOAT_EQ(x, 16.5f);
    EXPECT_FLOAT_EQ(z, 16.5f);
    EXPECT_FLOAT_EQ(y, 20.0f);
    ASSERT_TRUE(faf::editor::MarkerPosition(grid[17], x, y, z));
    EXPECT_FLOAT_EQ(x, 48.5f);
    EXPECT_FLOAT_EQ(z, 48.5f);
    EXPECT_EQ(faf::editor::MarkerTypeOf(grid[0]), "Air Path Node");
    // Names skip the taken one.
    EXPECT_EQ(grid[0].name, "AirPN01");
    // A corner has 3 neighbours, an edge 5, the inside 8.
    EXPECT_EQ(faf::editor::MarkerLinks(grid[0]).size(), 3U);
    EXPECT_EQ(faf::editor::MarkerLinks(grid[5]).size(), 5U);
    EXPECT_EQ(faf::editor::MarkerLinks(grid[17]).size(), 8U);
    // Links go both ways.
    const std::vector<std::string> links = faf::editor::MarkerLinks(grid[17]);
    EXPECT_NE(std::find(links.begin(), links.end(), grid[0].name), links.end());
    const std::vector<std::string> back = faf::editor::MarkerLinks(grid[0]);
    EXPECT_NE(std::find(back.begin(), back.end(), grid[17].name), back.end());
  }

  TEST(
    Markers,
    TypedValuesReadAndWriteBack
  )
  {
    using faf::editor::MarkerValue;
    const MarkerValue colour = faf::editor::ParseMarkerValue("STRING( 'ff800080' )");
    ASSERT_EQ(colour.kind, MarkerValue::Kind::String);
    EXPECT_EQ(colour.text, "ff800080");
    float rgba[4] = {};
    ASSERT_TRUE(faf::editor::MarkerColourText(colour.text, rgba));
    EXPECT_NEAR(rgba[3], 1.0f, 1e-6f);            // alpha first
    EXPECT_NEAR(rgba[0], 128.0f / 255.0f, 1e-6f); // then red
    EXPECT_NEAR(rgba[1], 0.0f, 1e-6f);
    EXPECT_NEAR(rgba[2], 128.0f / 255.0f, 1e-6f);
    EXPECT_EQ(faf::editor::MarkerColourOf(rgba), "ff800080");
    EXPECT_FALSE(faf::editor::MarkerColourText("Blank Marker", rgba));

    const MarkerValue position = faf::editor::ParseMarkerValue("VECTOR3( 672.5, 18.6797, 346.5 )");
    ASSERT_EQ(position.kind, MarkerValue::Kind::Vector3);
    EXPECT_FLOAT_EQ(position.number[1], 18.6797f);
    EXPECT_EQ(faf::editor::WriteMarkerValue(position), "VECTOR3( 672.5, 18.6797, 346.5 )");

    const MarkerValue amount = faf::editor::ParseMarkerValue("FLOAT( 100.000000 )");
    ASSERT_EQ(amount.kind, MarkerValue::Kind::Float);
    EXPECT_EQ(faf::editor::WriteMarkerValue(amount), "FLOAT( 100.000000 )");

    const MarkerValue hint = faf::editor::ParseMarkerValue("BOOLEAN( true )");
    ASSERT_EQ(hint.kind, MarkerValue::Kind::Bool);
    EXPECT_TRUE(hint.flag);
    EXPECT_EQ(faf::editor::WriteMarkerValue(hint), "BOOLEAN( true )");

    const MarkerValue type = faf::editor::ParseMarkerValue("STRING( 'Blank Marker' )");
    EXPECT_EQ(faf::editor::WriteMarkerValue(type), "STRING( 'Blank Marker' )");
    // Anything else is kept as written.
    const MarkerValue other = faf::editor::ParseMarkerValue("{ 'a', 'b' }");
    EXPECT_EQ(other.kind, MarkerValue::Kind::Raw);
    EXPECT_EQ(faf::editor::WriteMarkerValue(other), "{ 'a', 'b' }");
  }

  TEST(
    Markers,
    GameTemplatesAddTypesAndATypeChanges
  )
  {
    const std::string lua = "MarkerTemplates = {\n"
                            "    ['Mass'] = {\n        resource = true,\n        amount = 100,\n    },\n"
                            "    ['Mod Beacon'] = {\n        hint = true,\n        scale = 1.5,\n"
                            "\t\tprop = \"/env/common/props/markers/M_Expansion_prop.bp\",\n"
                            "\t\tcolor = \"ff123456\",\n        offset = VECTOR3(0,1,0),\n    },\n}\n";
    EXPECT_EQ(faf::editor::AddMarkerTemplates(lua), 1) << "Mass is built in already";
    const faf::editor::MarkerType* const beacon = faf::editor::FindMarkerType("Mod Beacon");
    ASSERT_NE(beacon, nullptr);
    EXPECT_STREQ(beacon->group, "Game");
    EXPECT_STREQ(beacon->color, "ff123456");
    EXPECT_STREQ(beacon->prop, "M_Expansion_prop.bp");
    ASSERT_EQ(beacon->extra.size(), 3U);
    EXPECT_EQ(beacon->extra[0].second, "BOOLEAN( true )");
    EXPECT_EQ(beacon->extra[1].second, "FLOAT( 1.500000 )");
    EXPECT_EQ(beacon->extra[2].first, "offset");
    EXPECT_EQ(faf::editor::AddMarkerTemplates(lua), 0) << "once";
    // A mass point turned into the beacon: Mass's own properties go, the beacon's come, the place stays.
    const faf::editor::MarkerType* const mass = faf::editor::FindMarkerType("Mass");
    ASSERT_NE(mass, nullptr);
    const faf::editor::SaveEntry point = faf::editor::NewMarker(*mass, "Mass 07", 10.0f, 20.0f, 30.0f);
    const faf::editor::SaveEntry changed = faf::editor::WithMarkerType(point, *beacon);
    EXPECT_EQ(changed.name, "Mass 07");
    EXPECT_EQ(faf::editor::MarkerTypeOf(changed), "Mod Beacon");
    EXPECT_TRUE(changed.Get("amount").empty());
    EXPECT_EQ(changed.Get("hint"), "BOOLEAN( true )");
    float x = 0, y = 0, z = 0;
    ASSERT_TRUE(faf::editor::MarkerPosition(changed, x, y, z));
    EXPECT_FLOAT_EQ(z, 30.0f);
  }
} // namespace
