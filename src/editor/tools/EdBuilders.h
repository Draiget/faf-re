#pragma once

#include <string>
#include <utility>
#include <vector>

namespace faf::editor
{
  /**
   * An army's platoon builders (the save's `PlatoonBuilders = { Builders = { name = { ... } } }`, FAF Studio's
   * Platoons panel, builders view): each builder's fields kept as Lua text, in their order, so one the editor doesn't
   * know (BuildConditions, BuildCallbacks) goes back as it was.
   */
  struct MissionBuilder
  {
    std::string name;
    std::vector<std::pair<std::string, std::string>> fields; // key, Lua value text
    [[nodiscard]] std::string Get(const std::string& key) const;
    void Set(const std::string& key, const std::string& value);
  };

  /** The builders of a `PlatoonBuilders` text; false with `error` when its Builders table can't be followed. */
  bool ParseBuilders(const std::string& text, std::vector<MissionBuilder>& builders, std::string& error);

  /** The `PlatoonBuilders` text for these builders (as the saves lay the table out). */
  [[nodiscard]] std::string FormatBuilders(const std::vector<MissionBuilder>& builders);

  /** A new builder with the fields the game's PBM reads, for a platoon template, at a base's location. */
  [[nodiscard]] MissionBuilder
  NewBuilder(const std::string& name, const std::string& platoonTemplate, const std::string& location);
} // namespace faf::editor
