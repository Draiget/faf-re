#pragma once

#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * The map's own fields in `_scenario.lua` (Map › Map info): its name, description, type, version and no-rush radius
   * as `ScenarioInfo` holds them. Reading takes the first `key = value` of the file (they come before the
   * configurations); writing replaces that value's text in place (the rest of the file as it was) or, when the file
   * has none, adds `key = value,` as the first line inside `ScenarioInfo = {`.
   */
  struct ScenarioField
  {
    const char* key;
    const char* label;
    bool text; // a string (else a number)
  };
  /** name, description, type, map_version, norushradius. */
  [[nodiscard]] const std::vector<ScenarioField>& ScenarioFields();

  /** The value of `key` (a string without its quotes, unescaped; a number as written), or false when there is none. */
  bool ReadScenarioField(const std::string& scenario, const std::string& key, std::string& value);
  /** The scenario with `key` set (a string quoted and escaped, a number as given); unchanged when it can't be placed.
   */
  [[nodiscard]] std::string
  WithScenarioField(const std::string& scenario, const std::string& key, const std::string& value, bool text);
  /**
   * Lobby slots' factions: `ScenarioInfo.Configurations.standard.factions[slot]`, a list of faction keys per start slot
   * (FAF's lobby.lua offers only those; without the table every slot offers all four). Empty: no restriction.
   */
  using SlotFactions = std::vector<std::vector<std::string>>;
  /** uef, aeon, cybran, seraphim. */
  [[nodiscard]] const std::vector<std::string>& FactionKeys();
  [[nodiscard]] SlotFactions ReadSlotFactions(const std::string& scenario);
  /**
   * The scenario with its slots' factions set (the `factions` table of the standard configuration replaced or added);
   * slots past the list, or a list of none or all four, offer all; nothing restricted removes the table.
   */
  [[nodiscard]] std::string WithSlotFactions(const std::string& scenario, const SlotFactions& factions);

  /** The text without a leading `<LOC id>` tag (as the game shows it). */
  [[nodiscard]] std::string WithoutLoc(const std::string& text);
} // namespace faf::editor
