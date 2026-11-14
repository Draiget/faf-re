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
  /** The text without a leading `<LOC id>` tag (as the game shows it). */
  [[nodiscard]] std::string WithoutLoc(const std::string& text);
} // namespace faf::editor
