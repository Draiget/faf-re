#pragma once

#include <map>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * The unit lab's fields (FAF Studio's bpedit field catalogue, limited to what the game's unit blueprint holds
   * natively): economy, defence, movement, intel, and per weapon its damage, radius, range, minimum range, rate of
   * fire and muzzle velocity. A field shows only when the unit has a value for it (not 0; a weapon's minimum range
   * also at 0).
   */
  struct UnitLabField
  {
    std::string key;   // a blueprint path or Weapon:<Label>.<Field>
    std::string label; // "Mass cost", "MainGun: Range"
    std::string group; // "Economy", "Weapon MainGun"
    double base = 0.0;
    double min = 0.0;
    double max = 0.0;
    double step = 1.0;
    int decimals = 0;
  };

  /** A unit's values as the lab reads them: blueprint paths, and each weapon's fields by label. */
  struct UnitLabSource
  {
    std::map<std::string, double> values;
    struct Weapon
    {
      std::string label;
      std::map<std::string, double> values; // Damage, MaxRadius, ...
    };
    std::vector<Weapon> weapons;
  };

  /** The unit's fields in the lab's order (economy, defence, movement, intel, then each weapon). */
  [[nodiscard]] std::vector<UnitLabField> UnitLabFields(const UnitLabSource& source);
  /** The field paths the lab reads (for the native reader and its tests). */
  [[nodiscard]] std::vector<std::string> UnitLabPaths();
  [[nodiscard]] std::vector<std::string> UnitLabWeaponFields();

  /**
   * A mod project's undo history (one per open project): each entry the project's changes before and after. Steps
   * with one merge key less than a second apart are one step (a slider drag).
   */
  class ModEditHistory
  {
  public:
    using Edits = std::map<std::string, std::map<std::string, double>>;

    /** Records a change already made; false when before and after are the same. */
    bool
    Record(const std::string& label, const Edits& before, const Edits& after, const std::string& mergeKey, double now);
    /** Puts the project back a step; false when there's none. */
    bool Undo(Edits& edits);
    bool Redo(Edits& edits);
    [[nodiscard]] const std::string* UndoName() const;
    [[nodiscard]] const std::string* RedoName() const;
    void Clear();
    [[nodiscard]] std::size_t Size() const noexcept
    {
      return mUndo.size();
    }

  private:
    struct Entry
    {
      std::string label;
      Edits before;
      Edits after;
      std::string mergeKey;
      double at = 0.0;
    };
    std::vector<Entry> mUndo;
    std::vector<Entry> mRedo;
  };
} // namespace faf::editor
