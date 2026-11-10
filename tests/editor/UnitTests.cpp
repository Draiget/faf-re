// The map editor's army units (src/editor/doc/EdUnits.cpp): an army's `Units` group reads into groups and units and
// writes back as the game's saves write it. With FAF_RETAIL_MAPS set to the game's maps folder, every army of every
// retail `_save.lua` round-trips byte for byte.

#include "editor/doc/EdSaveFile.h"
#include "editor/doc/EdUnits.h"

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace
{
  // SCMP_001's ARMY_9, as the game wrote it (two of its units).
  const char* const kGroup = R"(GROUP {
                orders = '',
                platoon = '',
                Units = {
                    ['INITIAL'] = GROUP {
                        orders = '',
                        platoon = '',
                        Units = {
                            ['GROUP_1'] = GROUP {
                                orders = '',
                                platoon = '',
                                Units = {
                                    ['UNIT_328'] = {
                                        type = 'ueb2101',
                                        orders = '',
                                        platoon = '',
                                        Position = { 502.500000, 20.281250, 515.500000 },
                                        Orientation = { 0.000000, 0.000000, 0.000000 },
                                    },
                                    ['UNIT_334'] = {
                                        type = 'ueb2301',
                                        orders = '',
                                        platoon = '',
                                        Position = { 498.500000, 20.250000, 511.500000 },
                                        Orientation = { 0.000000, 1.570796, 0.000000 },
                                    },
                                },
                            },
                        },
                    },
                },
            })";

  TEST(Units, AGroupReadsAndWritesBackAsTheGameWroteIt)
  {
    faf::editor::UnitGroup group;
    std::string error;
    ASSERT_TRUE(faf::editor::ParseUnitGroup(kGroup, group, error)) << error;
    std::vector<const faf::editor::SaveUnit*> units;
    faf::editor::CollectUnits(group, units);
    ASSERT_EQ(units.size(), 2u);
    EXPECT_EQ(units[0]->name, "UNIT_328");
    EXPECT_EQ(units[0]->type, "ueb2101");
    EXPECT_FLOAT_EQ(units[1]->position[2], 511.5f);
    EXPECT_NEAR(units[1]->orientation[1], 1.570796f, 1e-6f);
    EXPECT_EQ(faf::editor::HighestUnitNumber(group), 334);
    EXPECT_EQ(faf::editor::FormatUnitGroup(group, 12), kGroup);
  }

  TEST(Units, AddedAndRemovedUnitsWriteAndReadBack)
  {
    faf::editor::UnitGroup group;
    std::string error;
    ASSERT_TRUE(faf::editor::ParseUnitGroup(kGroup, group, error)) << error;
    faf::editor::SaveUnit tank;
    tank.name = "UNIT_335";
    tank.type = "uel0201";
    tank.position[0] = 400.5f;
    tank.position[1] = 20.0f;
    tank.position[2] = 410.5f;
    tank.orientation[1] = 0.5f;
    faf::editor::AddUnit(group, tank);
    // UNIT_328 goes: UNIT_334 stays in GROUP_1, the tank sits at INITIAL's end.
    ASSERT_TRUE(faf::editor::RemoveUnit(group, "UNIT_328"));
    EXPECT_FALSE(faf::editor::RemoveUnit(group, "UNIT_328"));
    faf::editor::UnitGroup back;
    ASSERT_TRUE(faf::editor::ParseUnitGroup(faf::editor::FormatUnitGroup(group, 12), back, error)) << error;
    std::vector<const faf::editor::SaveUnit*> units;
    faf::editor::CollectUnits(back, units);
    ASSERT_EQ(units.size(), 2u);
    EXPECT_EQ(units[0]->name, "UNIT_334");
    EXPECT_EQ(units[1]->type, "uel0201");
    EXPECT_FLOAT_EQ(units[1]->position[2], 410.5f);
    EXPECT_EQ(faf::editor::HighestUnitNumber(back), 335);
    ASSERT_NE(faf::editor::FindUnit(back, "UNIT_335"), nullptr);
    // An army without INITIAL gets one.
    faf::editor::UnitGroup empty;
    ASSERT_TRUE(faf::editor::ParseUnitGroup("GROUP { orders = '', platoon = '', Units = { } }", empty, error)) << error;
    faf::editor::AddUnit(empty, tank);
    ASSERT_EQ(empty.groups.size(), 1u);
    EXPECT_EQ(empty.groups[0].name, "INITIAL");
    EXPECT_EQ(empty.groups[0].units.size(), 1u);
  }

  TEST(Units, AnEmptyGroupAndBadText)
  {
    faf::editor::UnitGroup group;
    std::string error;
    ASSERT_TRUE(faf::editor::ParseUnitGroup("GROUP { orders = '', platoon = '', Units = { } }", group, error)) << error;
    EXPECT_TRUE(group.order.empty());
    EXPECT_FALSE(faf::editor::ParseUnitGroup("GROUP { weather = 'rain' }", group, error));
    EXPECT_FALSE(error.empty());
  }

  TEST(Units, EveryRetailArmyRoundTrips)
  {
    const char* const folder = std::getenv("FAF_RETAIL_MAPS");
    if (folder == nullptr) {
      GTEST_SKIP() << "FAF_RETAIL_MAPS is not set";
    }
    int armies = 0;
    int units = 0;
    for (const auto& map : std::filesystem::directory_iterator(folder)) {
      for (const auto& file : std::filesystem::directory_iterator(map.path())) {
        const std::string name = file.path().filename().string();
        if (name.size() < 9 || name.substr(name.size() - 9) != "_save.lua") {
          continue;
        }
        std::ifstream in(file.path(), std::ios::binary);
        std::stringstream text;
        text << in.rdbuf();
        faf::editor::SaveFile save;
        std::string error;
        ASSERT_TRUE(save.Parse(text.str(), error)) << file.path() << ": " << error;
        for (const faf::editor::SaveEntry& army : save.Armies()) {
          const std::string value = army.Get("Units");
          faf::editor::UnitGroup group;
          ASSERT_TRUE(faf::editor::ParseUnitGroup(value, group, error)) << file.path() << " " << army.name << ": " << error;
          const std::string written = faf::editor::FormatUnitGroup(group, 12);
          if (written != value) {
            // Where they part, with a little around it.
            std::size_t at = 0;
            while (at < written.size() && at < value.size() && written[at] == value[at]) {
              ++at;
            }
            const std::size_t from = at > 80 ? at - 80 : 0;
            ADD_FAILURE() << file.path() << " " << army.name << " differs at " << at << " | written: " << written.substr(from, 160)
                          << " | read: " << value.substr(from, 160);
          }
          std::vector<const faf::editor::SaveUnit*> all;
          faf::editor::CollectUnits(group, all);
          units += static_cast<int>(all.size());
          ++armies;
        }
      }
    }
    EXPECT_GT(armies, 0);
    std::printf("retail: %d armies, %d units round-tripped\n", armies, units);
  }
  TEST(Units, GroupsAreAddedRenamedMovedIntoAndRemoved)
  {
    faf::editor::UnitGroup root;
    std::string error;
    ASSERT_TRUE(faf::editor::ParseUnitGroup(kGroup, root, error)) << error;
    // A group beside GROUP_1 in INITIAL; a name taken there is refused.
    ASSERT_TRUE(faf::editor::AddGroup(root, {"INITIAL"}, "Defense"));
    EXPECT_FALSE(faf::editor::AddGroup(root, {"INITIAL"}, "Defense"));
    // UNIT_334 into it.
    EXPECT_EQ(faf::editor::MoveUnitsTo(root, {"UNIT_334", "UNIT_999"}, {"INITIAL", "Defense"}), 1);
    EXPECT_EQ(faf::editor::UnitNamesIn(*faf::editor::GroupAt(root, {"INITIAL", "Defense"})), (std::vector<std::string>{"UNIT_334"}));
    EXPECT_EQ(faf::editor::UnitNamesIn(*faf::editor::GroupAt(root, {"INITIAL", "GROUP_1"})), (std::vector<std::string>{"UNIT_328"}));
    // Renamed, and still found under the new name only.
    ASSERT_TRUE(faf::editor::RenameGroup(root, {"INITIAL", "Defense"}, "Defenses"));
    EXPECT_EQ(faf::editor::GroupAt(root, {"INITIAL", "Defense"}), nullptr);
    EXPECT_FALSE(faf::editor::RenameGroup(root, {"INITIAL", "Defenses"}, "GROUP_1"));
    // Written and read again, the tree is the same.
    faf::editor::UnitGroup again;
    ASSERT_TRUE(faf::editor::ParseUnitGroup(faf::editor::FormatUnitGroup(root, 12), again, error)) << error;
    EXPECT_TRUE(again == root);
    // GROUP_1 removed: its unit goes up into INITIAL, in GROUP_1's place (before Defenses).
    ASSERT_TRUE(faf::editor::RemoveGroup(root, {"INITIAL", "GROUP_1"}));
    const faf::editor::UnitGroup& initial = *faf::editor::GroupAt(root, {"INITIAL"});
    ASSERT_EQ(initial.order.size(), 2u);
    EXPECT_EQ(initial.order[0].unit, 0);
    EXPECT_EQ(initial.units[0].name, "UNIT_328");
    EXPECT_EQ(initial.order[1].group, 0);
    EXPECT_EQ(initial.groups[0].name, "Defenses");
    EXPECT_EQ(faf::editor::UnitNamesIn(root), (std::vector<std::string>{"UNIT_328", "UNIT_334"}));
    EXPECT_FALSE(faf::editor::RemoveGroup(root, {}));
    ASSERT_TRUE(faf::editor::ParseUnitGroup(faf::editor::FormatUnitGroup(root, 12), again, error)) << error;
    EXPECT_TRUE(again == root);
  }
} // namespace
