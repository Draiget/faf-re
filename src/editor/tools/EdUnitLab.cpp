#include "editor/tools/EdUnitLab.h"

#include <algorithm>
#include <cmath>

namespace faf::editor
{
  namespace
  {
    struct FieldDef
    {
      const char* key;
      const char* label;
      const char* group;
      int decimals;
    };

    // Studio's UNIT_FIELDS without the ones only FAF's Lua tables hold (production, upkeep, shield health and regen),
    // with the storage the native blueprint has.
    const FieldDef kUnitFields[] = {
      {"Economy.BuildCostMass", "Mass cost", "Economy", 0},
      {"Economy.BuildCostEnergy", "Energy cost", "Economy", 0},
      {"Economy.BuildTime", "Build time", "Economy", 0},
      {"Economy.BuildRate", "Build rate", "Economy", 1},
      {"Economy.StorageMass", "Mass storage", "Economy", 0},
      {"Economy.StorageEnergy", "Energy storage", "Economy", 0},
      {"Defense.MaxHealth", "Health", "Defence", 0},
      {"Defense.RegenRate", "Regeneration / s", "Defence", 1},
      {"Defense.Shield.ShieldSize", "Shield diameter", "Defence", 1},
      {"Physics.MaxSpeed", "Top speed", "Movement", 2},
      {"Physics.MaxAcceleration", "Acceleration", "Movement", 2},
      {"Physics.MaxBrake", "Braking", "Movement", 2},
      {"Physics.TurnRate", "Turn rate", "Movement", 1},
      {"Intel.VisionRadius", "Vision radius", "Intel", 0},
      {"Intel.WaterVisionRadius", "Water vision radius", "Intel", 0},
      {"Intel.RadarRadius", "Radar radius", "Intel", 0},
      {"Intel.SonarRadius", "Sonar radius", "Intel", 0},
      {"Intel.OmniRadius", "Omni radius", "Intel", 0},
    };

    const FieldDef kWeaponFields[] = {
      {"Damage", "Damage", "", 0},
      {"DamageRadius", "Damage radius", "", 1},
      {"MaxRadius", "Range", "", 1},
      {"MinRadius", "Minimum range", "", 1},
      {"RateOfFire", "Rate of fire", "", 2},
      {"MuzzleVelocity", "Muzzle velocity", "", 1},
    };

    /** Studio's Range: from 0 to four times the game's value (at least 10), whole tens for whole numbers. */
    void Range(
      UnitLabField& f
    )
    {
      f.step = f.decimals == 0 ? 1.0 : std::pow(10.0, -f.decimals);
      if (f.decimals >= 2) {
        f.step = 0.05;
      }
      f.max = std::max(10.0, f.base * 4.0);
      if (f.decimals == 0) {
        f.max = std::ceil(f.max / 10.0) * 10.0;
      }
      f.min = 0.0;
    }
  } // namespace

  std::vector<std::string> UnitLabPaths()
  {
    std::vector<std::string> out;
    for (const FieldDef& f : kUnitFields) {
      out.emplace_back(f.key);
    }
    return out;
  }

  std::vector<std::string> UnitLabWeaponFields()
  {
    std::vector<std::string> out;
    for (const FieldDef& f : kWeaponFields) {
      out.emplace_back(f.key);
    }
    return out;
  }

  std::vector<UnitLabField> UnitLabFields(
    const UnitLabSource& source
  )
  {
    std::vector<UnitLabField> out;
    for (const FieldDef& def : kUnitFields) {
      const auto it = source.values.find(def.key);
      if (it == source.values.end() || !std::isfinite(it->second) || it->second == 0.0) {
        continue;
      }
      UnitLabField f{def.key, def.label, def.group, it->second};
      f.decimals = def.decimals;
      Range(f);
      out.push_back(f);
    }
    for (const UnitLabSource::Weapon& w : source.weapons) {
      if (w.label.empty()) {
        continue;
      }
      for (const FieldDef& def : kWeaponFields) {
        const auto it = w.values.find(def.key);
        if (it == w.values.end() || !std::isfinite(it->second)) {
          continue;
        }
        if (it->second == 0.0 && std::string(def.key) != "MinRadius") {
          continue;
        }
        UnitLabField f{
          "Weapon:" + w.label + "." + def.key, w.label + ": " + def.label, "Weapon " + w.label, it->second
        };
        f.decimals = def.decimals;
        Range(f);
        out.push_back(f);
      }
    }
    return out;
  }

  bool ModEditHistory::Record(
    const std::string& label,
    const Edits& before,
    const Edits& after,
    const std::string& mergeKey,
    const double now
  )
  {
    if (before == after) {
      return false;
    }
    mRedo.clear();
    if (!mergeKey.empty() && !mUndo.empty() && mUndo.back().mergeKey == mergeKey && now - mUndo.back().at < 1.0) {
      mUndo.back().after = after;
      mUndo.back().at = now;
      return true;
    }
    mUndo.push_back({label, before, after, mergeKey, now});
    if (mUndo.size() > 500) {
      mUndo.erase(mUndo.begin());
    }
    return true;
  }

  bool ModEditHistory::Undo(
    Edits& edits
  )
  {
    if (mUndo.empty()) {
      return false;
    }
    Entry entry = std::move(mUndo.back());
    mUndo.pop_back();
    edits = entry.before;
    entry.mergeKey.clear(); // a redone step never takes a later drag in
    mRedo.push_back(std::move(entry));
    return true;
  }

  bool ModEditHistory::Redo(
    Edits& edits
  )
  {
    if (mRedo.empty()) {
      return false;
    }
    Entry entry = std::move(mRedo.back());
    mRedo.pop_back();
    edits = entry.after;
    mUndo.push_back(std::move(entry));
    return true;
  }

  const std::string* ModEditHistory::UndoName() const
  {
    return mUndo.empty() ? nullptr : &mUndo.back().label;
  }

  const std::string* ModEditHistory::RedoName() const
  {
    return mRedo.empty() ? nullptr : &mRedo.back().label;
  }

  void ModEditHistory::Clear()
  {
    mUndo.clear();
    mRedo.clear();
  }
} // namespace faf::editor
