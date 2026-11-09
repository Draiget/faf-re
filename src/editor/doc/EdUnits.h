#pragma once

#include <string>
#include <vector>

namespace faf::editor
{
  /** A unit of an army's `_save.lua` group: `['UNIT_328'] = { type = 'ueb2101', orders, platoon, Position, Orientation }`. */
  struct SaveUnit
  {
    std::string name;
    /** The unit blueprint id (`ueb2101`). */
    std::string type;
    std::string orders;
    std::string platoon;
    float position[3] = {0.0f, 0.0f, 0.0f};
    /** Euler angles in radians, as the saves write them (y is the heading). */
    float orientation[3] = {0.0f, 0.0f, 0.0f};

    bool operator==(const SaveUnit& other) const;
  };

  /** A `GROUP { orders, platoon, Units = { ... } }`: its own groups and units, in the file's order. */
  struct UnitGroup
  {
    std::string name;
    std::string orders;
    std::string platoon;
    /** The members in order: a group or a unit each (one of the two indexes is -1). */
    struct Member
    {
      int group = -1;
      int unit = -1;
    };
    std::vector<UnitGroup> groups;
    std::vector<SaveUnit> units;
    std::vector<Member> order;
    /** The line end of the text it was read from (CR LF in the game's saves), written back alike. */
    std::string newline = "\n";

    bool operator==(const UnitGroup& other) const;
  };

  /**
   * Reads an army's `Units` value (`GROUP { ... }` as the save holds it). False, with `error`, for text it can't
   * read; the caller then leaves the army's text alone.
   */
  bool ParseUnitGroup(const std::string& text, UnitGroup& group, std::string& error);

  /**
   * Writes a group as the game's saves write it, its closing brace at `indent` spaces (the army's properties sit at
   * 12): what ParseUnitGroup read from a game save writes back the same.
   */
  std::string FormatUnitGroup(const UnitGroup& group, int indent);

  /** Every unit of a group and its groups, depth first in the file's order, with the path of groups to it. */
  void CollectUnits(const UnitGroup& group, std::vector<const SaveUnit*>& units);

  /** The highest `n` of the `UNIT_n` names in the groups (0 when none), for the next unit's name. */
  int HighestUnitNumber(const UnitGroup& group);

  /** The unit of this name in the group or its groups, or null. */
  SaveUnit* FindUnit(UnitGroup& group, const std::string& name);

  /** Removes the unit of this name from whichever group holds it; the others keep their order. False when none. */
  bool RemoveUnit(UnitGroup& group, const std::string& name);

  /** Adds a unit at the end of the army's INITIAL group (made when the army has none), as the game's units start. */
  void AddUnit(UnitGroup& root, SaveUnit unit);
} // namespace faf::editor
