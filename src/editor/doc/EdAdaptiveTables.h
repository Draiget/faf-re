#pragma once

#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * An adaptive map's `_tables.lua` (the "Ultimate maps" script by CookieNoob and KeyBlue that FAF's adaptive maps use;
   * FAForeverMapEditor writes the same file): which mass and hydrocarbon markers spawn with which army, and which belong
   * to the lobby options' groups. The script reads each entry as a marker's number ("Mass 07" is 7, "Mass 12" is 12,
   * MassString/HydroString) or a string put after the type's name. Here entries are kept as the markers' names.
   */
  struct AdaptiveTables
  {
    /** `maxPlayerOnMap`. */
    int maxPlayers = 16;
    /** `spwnMexArmy` and `spwnHydroArmy`: by army, ARMY_1 first. */
    std::vector<std::vector<std::string>> mexArmy;
    std::vector<std::vector<std::string>> hydroArmy;
    /** The option tables (KnownOptionTables), each as its groups: an option's key k removes groups k and above. */
    std::vector<std::pair<std::string, std::vector<std::vector<std::string>>>> options;
    /** `forwardCrazyrushMexes` and `crazyrushOneMexes`: flat lists. */
    std::vector<std::string> forwardCrazyrush;
    std::vector<std::string> crazyrushOne;

    bool operator==(const AdaptiveTables& other) const
    {
      return maxPlayers == other.maxPlayers && mexArmy == other.mexArmy && hydroArmy == other.hydroArmy && options == other.options &&
             forwardCrazyrush == other.forwardCrazyrush && crazyrushOne == other.crazyrushOne;
    }
  };

  /** The script's option tables in its order, and whether each holds hydrocarbons (else mass). */
  struct OptionTable
  {
    const char* name;
    const char* label;
    bool hydro;
  };
  const std::vector<OptionTable>& KnownOptionTables();

  /** Reads the tables the script uses from a `_tables.lua`'s text; others are left to the text. False with `error`. */
  bool ParseAdaptiveTables(const std::string& text, AdaptiveTables& tables, std::string& error);

  /**
   * The text with the tables written in: each one the script uses replaced where it is (the rest of the file, its
   * comments and the mapper's own tables, kept), appended when missing. An empty `text` gives a new file.
   */
  std::string WithAdaptiveTables(const std::string& text, const AdaptiveTables& tables);

  /** The `/maps/.../x_tables.lua` the map's `_script.lua` imports, or empty (not an adaptive script). */
  std::string AdaptiveTablesPath(const std::string& script);
  /** `_scenario.lua` with `AdaptiveMap = true` in its ScenarioInfo (set where it is, else added first). */
  std::string WithScenarioAdaptive(const std::string& scenario);

  /** The entry the script reads for a marker: 7 for "Mass 07", 12 for "Mass 12", '7' for "Mass 7"; empty when not that type. */
  std::string AdaptiveEntry(const std::string& markerName, bool hydro);
  /** The marker an entry names ("7" gives "Mass 07", "'7'" gives "Mass 7"). */
  std::string AdaptiveMarkerName(const std::string& entry, bool hydro);
} // namespace faf::editor
