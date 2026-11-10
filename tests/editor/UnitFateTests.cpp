// What becomes of a map's unit, and its wreck's value (src/editor/doc/EdUnitFate.cpp), as FAF's Lua decides them.

#include "editor/doc/EdUnitFate.h"

#include <gtest/gtest.h>

namespace
{
  using faf::editor::UnitFate;

  faf::editor::UnitGroup Army()
  {
    faf::editor::UnitGroup root;
    faf::editor::UnitGroup initial;
    initial.name = "INITIAL";
    initial.units.push_back({"UNIT_1", "uel0101", "", "", {}, {}});
    faf::editor::UnitGroup wreckage;
    wreckage.name = "WRECKAGE";
    wreckage.units.push_back({"UNIT_2", "urs0201", "", "", {}, {}});
    faf::editor::UnitGroup optional;
    optional.name = "Optional_Wreckage_2";
    faf::editor::UnitGroup inner;
    inner.name = "Middle";
    inner.units.push_back({"UNIT_3", "urs0201", "", "", {}, {}});
    optional.groups.push_back(inner);
    root.groups = {initial, wreckage, optional};
    return root;
  }

  // As DualGap Adaptive's script creates its optional groups.
  const char* const kScript = R"lua(
    if optional_wreckage > 1 then
        for w = 2, optional_wreckage do
            ScenarioUtils.CreateArmyGroup('ARMY_17', 'Optional_Wreckage_' .. w, true)
        end
    end
    if(optional_civilian_base == 2) then
        ScenarioUtils.CreateArmyGroup('ARMY_17', 'Optional_Civilian_Base_2', true)
    elseif(optional_civilian_base == 3) then
        ScenarioUtils.CreateArmyGroup('ARMY_17', 'Optional_Civilian_Base_2', false)
    end
    ScenarioUtils.CreateArmyGroup('ARMY_17', 'Outpost', false)
    ScenarioUtils.CreateArmyGroupAsPlatoon('ARMY_17', 'Patrol', 'GrowthFormation')
)lua";

  TEST(UnitFate, PathToTheUnit)
  {
    const faf::editor::UnitGroup root = Army();
    EXPECT_EQ(faf::editor::UnitGroupPath(root, "UNIT_3"), (std::vector<std::string>{"Optional_Wreckage_2", "Middle"}));
    EXPECT_EQ(faf::editor::UnitGroupPath(root, "UNIT_1"), (std::vector<std::string>{"INITIAL"}));
    EXPECT_TRUE(faf::editor::UnitGroupPath(root, "UNIT_9").empty());
  }

  TEST(UnitFate, TheGamesOwnGroups)
  {
    EXPECT_EQ(faf::editor::FateOfUnit({"INITIAL"}, false, "").kind, UnitFate::Kind::Unit);
    EXPECT_EQ(faf::editor::FateOfUnit({"INITIAL", "Base"}, true, "").kind, UnitFate::Kind::Unit);
    EXPECT_NE(faf::editor::FateOfUnit({"INITIAL"}, true, "").text.find("Civilians"), std::string::npos);
    EXPECT_EQ(faf::editor::FateOfUnit({"WRECKAGE"}, true, "").kind, UnitFate::Kind::Wreck);
    // WRECKAGE inside INITIAL still becomes wrecks.
    EXPECT_EQ(faf::editor::FateOfUnit({"INITIAL", "WRECKAGE"}, true, "").kind, UnitFate::Kind::Wreck);
  }

  TEST(UnitFate, GroupsTheScriptCreates)
  {
    const UnitFate prefix = faf::editor::FateOfUnit({"Optional_Wreckage_2", "Middle"}, true, kScript);
    EXPECT_EQ(prefix.kind, UnitFate::Kind::ScriptWreck);
    EXPECT_EQ(prefix.group, "Optional_Wreckage_2");
    // Made as wrecks for one lobby option and as units for another.
    EXPECT_EQ(faf::editor::FateOfUnit({"Optional_Civilian_Base_2"}, true, kScript).kind, UnitFate::Kind::ScriptEither);
    EXPECT_EQ(faf::editor::FateOfUnit({"Outpost"}, true, kScript).kind, UnitFate::Kind::ScriptUnit);
    EXPECT_EQ(faf::editor::FateOfUnit({"Patrol"}, true, kScript).kind, UnitFate::Kind::ScriptUnit);
    // Exact names only match exactly.
    EXPECT_EQ(faf::editor::FateOfUnit({"Optional_Civilian_Base_3"}, true, kScript).kind, UnitFate::Kind::Never);
    EXPECT_EQ(faf::editor::FateOfUnit({"Spare"}, true, kScript).kind, UnitFate::Kind::Never);
  }

  // URS0201 (Salem class destroyer) as FAF ships it: 2250 mass, 15000 energy, TECH2, Wreckage MassMult 0.9, EnergyMult 0.
  const char* const kDestroyer = R"lua(UnitBlueprint {
    Categories = {
        "SELECTABLE",
        "CYBRAN",
        "NAVAL",
        "TECH2",
        "DESTROYER",
    },
    Economy = {
        BuildCostEnergy = 15000,
        BuildCostMass = 2250,
    },
    Wreckage = {
        Blueprint = "/props/DefaultWreckage/DefaultWreckage_prop.bp",
        EnergyMult = 0,
        HealthMult = 0.9,
        MassMult = 0.9,
        ReclaimTimeMultiplier = 1,
    },
}
)lua";

  TEST(UnitFate, WreckValueAsUnitLuaMakesIt)
  {
    const faf::editor::WreckValue dry = faf::editor::WreckOfUnit(kDestroyer, 2250.0, 15000.0, false);
    EXPECT_TRUE(dry.exists);
    EXPECT_DOUBLE_EQ(dry.mass, 2250.0 * 0.9 * 0.8);
    EXPECT_DOUBLE_EQ(dry.energy, 0.0);
    const faf::editor::WreckValue wet = faf::editor::WreckOfUnit(kDestroyer, 2250.0, 15000.0, true);
    EXPECT_DOUBLE_EQ(wet.mass, 2250.0 * 0.9 * 0.8 * 0.6);
    // No Wreckage table: no wreck.
    EXPECT_FALSE(faf::editor::WreckOfUnit("UnitBlueprint { Economy = { BuildCostMass = 50 } }", 50.0, 0.0, false).exists);
    // A naval unit without one gets FAF's default (Blueprints.lua): UES0103, a tech 1 frigate of 280 mass.
    const faf::editor::WreckValue frigate =
      faf::editor::WreckOfUnit("UnitBlueprint { Categories = { \"UEF\", \"NAVAL\", \"TECH1\", }, Economy = { BuildCostMass = 280 } }", 280.0,
                               2000.0, false);
    EXPECT_TRUE(frigate.exists);
    EXPECT_DOUBLE_EQ(frigate.mass, 280.0 * 0.9 * 0.9);
    EXPECT_DOUBLE_EQ(frigate.energy, 0.0);
  }
} // namespace
