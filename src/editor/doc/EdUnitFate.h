#pragma once

#include <string>
#include <vector>

#include "editor/doc/EdUnits.h"

namespace faf::editor
{
  /**
   * What becomes of a unit a map's `_save.lua` holds, read from FAF's Lua (lua/sim/ScenarioUtilities.lua): units are only
   * data until something creates their group. At the start the game creates each army's `INITIAL` group (a civilian
   * army's unless the lobby's Civilians option is "removed") and turns its `WRECKAGE` group into wrecks; any other group
   * exists only when the map's script creates it (`CreateArmyGroup(army, group, wreckage)`).
   */
  struct UnitFate
  {
    enum class Kind
    {
      /** In INITIAL: a unit from the start. */
      Unit,
      /** In WRECKAGE: a wreck from the start. */
      Wreck,
      /** In a group the map's script creates as units. */
      ScriptUnit,
      /** In a group the map's script creates as wrecks (`CreateArmyGroup(..., true)`). */
      ScriptWreck,
      /** In a group nothing creates (the script doesn't name it): never in a game. */
      Never,
    };
    Kind kind = Kind::Never;
    /** The group that decides it (`INITIAL`, `Optional_Wreckage_2`). */
    std::string group;
    /** One sentence for the Properties panel. */
    std::string text;
  };

  /** The names of the groups from under the army's root down to the unit's (empty when the unit isn't there). */
  std::vector<std::string> UnitGroupPath(const UnitGroup& root, const std::string& unit);

  /** The fate of a unit in the groups `path` of an army (`civilian`: not a player slot), given the map's script text. */
  UnitFate FateOfUnit(const std::vector<std::string>& path, bool civilian, const std::string& script);

  /**
   * A unit's wreck as Unit.lua's CreateWreckageProp makes it: the build costs times the blueprint's Wreckage MassMult
   * and EnergyMult, the mass times 0.9 / 0.8 / 0.7 / 0.6 by TechCategory (TECH1 / TECH2 / TECH3 / EXPERIMENTAL), and
   * both times 0.6 under water. `blueprintText` is the unit's `.bp`; `exists` false when it has no Wreckage Blueprint.
   */
  struct WreckValue
  {
    bool exists = false;
    double mass = 0.0;
    double energy = 0.0;
  };
  WreckValue WreckOfUnit(const std::string& blueprintText, double buildCostMass, double buildCostEnergy, bool underwater);
} // namespace faf::editor
