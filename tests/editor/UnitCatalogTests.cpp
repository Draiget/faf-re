// The Units tool's browser (src/editor/ui/EdUnitCatalog.cpp): a unit's faction, kind and tech from its categories,
// the filter in the build menu's order, and the chips' counts.

#include "editor/ui/EdUnitCatalog.h"

#include <gtest/gtest.h>

using faf::editor::EdUnitFilter;
using faf::editor::EdUnitInfo;
using faf::editor::FactionCounts;
using faf::editor::FilterUnits;
using faf::editor::KindCounts;
using faf::editor::UnitInfoFrom;

namespace
{
  std::vector<EdUnitInfo> Units()
  {
    return {
      UnitInfoFrom("uel0201", "MA12 Striker", {"UEF", "MOBILE", "LAND", "TECH1", "DIRECTFIRE"}),
      UnitInfoFrom("uaa0303", "Corona", {"AEON", "MOBILE", "AIR", "TECH3", "ANTIAIR"}),
      UnitInfoFrom("urb0102", "Air Factory", {"CYBRAN", "STRUCTURE", "AIR", "FACTORY", "TECH1"}),
      UnitInfoFrom("xsl0401", "Ythotha", {"SERAPHIM", "MOBILE", "LAND", "EXPERIMENTAL"}),
      UnitInfoFrom("ues0103", "Thunderhead", {"UEF", "MOBILE", "NAVAL", "TECH1"}),
      UnitInfoFrom("uel0101", "LAB", {"UEF", "MOBILE", "LAND", "TECH1"}),
      UnitInfoFrom("civ01", "Truck", {"CIVILIAN", "LAND"}),
    };
  }

  TEST(
    UnitCatalog,
    GroupsFromCategories
  )
  {
    const auto units = Units();
    EXPECT_EQ(units[0].faction, 0);
    EXPECT_EQ(units[0].kind, 0) << "land";
    EXPECT_EQ(units[0].tech, 0) << "tech 1";
    EXPECT_EQ(units[1].kind, 1) << "air";
    EXPECT_EQ(units[1].tech, 2);
    EXPECT_EQ(units[2].kind, 3) << "an air factory is a building";
    EXPECT_EQ(units[3].tech, 3) << "experimental";
    EXPECT_EQ(units[4].kind, 2) << "naval";
    EXPECT_EQ(units[6].faction, 4) << "no faction: Other";
    EXPECT_EQ(units[6].tech, 4);
    EXPECT_EQ(UnitInfoFrom("x", "y", {"uef", "tech2"}).tech, 1) << "case aside";
  }

  TEST(
    UnitCatalog,
    FilterInTheBuildMenusOrder
  )
  {
    const auto units = Units();
    EdUnitFilter uef;
    uef.faction = 0;
    const auto shown = FilterUnits(units, uef);
    ASSERT_EQ(shown.size(), 3u);
    EXPECT_EQ(units[shown[0]].id, "uel0101") << "tech 1 first, by id";
    EXPECT_EQ(units[shown[1]].id, "uel0201");
    EXPECT_EQ(units[shown[2]].id, "ues0103");
    EdUnitFilter land;
    land.kind = 0;
    land.text = "strik";
    const auto strikers = FilterUnits(units, land);
    ASSERT_EQ(strikers.size(), 1u);
    EXPECT_EQ(units[strikers[0]].id, "uel0201");
    EdUnitFilter words;
    words.text = "air fac";
    EXPECT_EQ(FilterUnits(units, words).size(), 1u) << "every word, in the id or the name";
    EXPECT_EQ(FilterUnits(units, EdUnitFilter{}).size(), units.size());
  }

  TEST(
    UnitCatalog,
    ChipsCountWhatTheyWouldShow
  )
  {
    const auto units = Units();
    EdUnitFilter land;
    land.kind = 0;
    const auto factions = FactionCounts(units, land);
    EXPECT_EQ(factions[0], 2) << "UEF land units: the LAB and the Striker";
    EXPECT_EQ(factions[3], 1);
    EXPECT_EQ(factions[4], 1) << "the civilian truck";
    EdUnitFilter uef;
    uef.faction = 0;
    const auto kinds = KindCounts(units, uef);
    EXPECT_EQ(kinds[0], 2);
    EXPECT_EQ(kinds[2], 1);
    EXPECT_EQ(kinds[1], 0);
  }
} // namespace
