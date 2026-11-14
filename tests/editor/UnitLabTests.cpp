#include "editor/tools/EdUnitLab.h"

#include <gtest/gtest.h>

namespace faf::editor
{
  namespace
  {
    UnitLabSource Tank()
    {
      UnitLabSource s;
      for (const std::string& path : UnitLabPaths()) {
        s.values[path] = 0.0;
      }
      s.values["Economy.BuildCostMass"] = 54.0;
      s.values["Defense.MaxHealth"] = 300.0;
      s.values["Physics.MaxSpeed"] = 3.1;
      s.values["Intel.VisionRadius"] = 20.0;
      UnitLabSource::Weapon gun;
      gun.label = "MainGun";
      gun.values = {
        {"Damage", 12.0}, {"DamageRadius", 0.0}, {"MaxRadius", 18.0}, {"MinRadius", 0.0}, {"RateOfFire", 1.0}
      };
      s.weapons.push_back(gun);
      UnitLabSource::Weapon dummy; // a weapon without a label (a death weapon's helper)
      dummy.values = {{"Damage", 5.0}};
      s.weapons.push_back(dummy);
      return s;
    }
  } // namespace

  TEST(
    UnitLab,
    FieldsAreTheOnesTheUnitHasWithStudiosRanges
  )
  {
    const std::vector<UnitLabField> f = UnitLabFields(Tank());
    std::vector<std::string> keys;
    for (const UnitLabField& field : f) {
      keys.push_back(field.key);
    }
    EXPECT_EQ(
      keys,
      (std::vector<std::string>{
        "Economy.BuildCostMass",
        "Defense.MaxHealth",
        "Physics.MaxSpeed",
        "Intel.VisionRadius",
        "Weapon:MainGun.Damage",
        "Weapon:MainGun.MaxRadius",
        "Weapon:MainGun.MinRadius",
        "Weapon:MainGun.RateOfFire"
      })
    ) << "zeros left out but a weapon's minimum range; the unlabelled weapon left out";
    EXPECT_EQ(f[0].group, "Economy");
    EXPECT_DOUBLE_EQ(f[0].max, 220.0) << "4 x 54 = 216, to whole tens";
    EXPECT_DOUBLE_EQ(f[0].step, 1.0);
    EXPECT_DOUBLE_EQ(f[2].max, 12.4) << "4 x 3.1";
    EXPECT_DOUBLE_EQ(f[2].step, 0.05) << "two decimals step by 0.05";
    EXPECT_EQ(f[4].label, "MainGun: Damage");
    EXPECT_EQ(f[4].group, "Weapon MainGun");
    EXPECT_DOUBLE_EQ(f[6].max, 10.0) << "at least 10";
  }

  TEST(
    UnitLab,
    HistoryUndoesRedoesAndFoldsADrag
  )
  {
    ModEditHistory h;
    ModEditHistory::Edits e;
    ModEditHistory::Edits before = e;
    e["uel0201"]["Economy.BuildCostMass"] = 55;
    EXPECT_TRUE(h.Record("mass", before, e, "drag", 0.0));
    before = e;
    e["uel0201"]["Economy.BuildCostMass"] = 60;
    EXPECT_TRUE(h.Record("mass", before, e, "drag", 0.3));
    EXPECT_EQ(h.Size(), 1U) << "one drag, one step";
    before = e;
    e["uel0201"]["Defense.MaxHealth"] = 400;
    EXPECT_TRUE(h.Record("health", before, e, "drag2", 0.4));
    EXPECT_FALSE(h.Record("nothing", e, e, "", 0.5));
    EXPECT_EQ(*h.UndoName(), "health");
    ASSERT_TRUE(h.Undo(e));
    EXPECT_EQ(e.at("uel0201").count("Defense.MaxHealth"), 0U);
    ASSERT_TRUE(h.Undo(e));
    EXPECT_TRUE(e.empty());
    EXPECT_FALSE(h.Undo(e));
    ASSERT_TRUE(h.Redo(e));
    EXPECT_DOUBLE_EQ(e.at("uel0201").at("Economy.BuildCostMass"), 60);
    // A step after an undo drops the redo.
    before = e;
    e["ura0203"]["Physics.MaxSpeed"] = 9;
    EXPECT_TRUE(h.Record("speed", before, e, "", 1.0));
    EXPECT_EQ(h.RedoName(), nullptr);
    // A redone step doesn't take a later drag of the same key in.
    ASSERT_TRUE(h.Undo(e));
    ASSERT_TRUE(h.Redo(e));
    before = e;
    e["ura0203"]["Physics.MaxSpeed"] = 10;
    EXPECT_TRUE(h.Record("speed", before, e, "", 1.1));
    EXPECT_EQ(h.Size(), 3U);
  }
} // namespace faf::editor
