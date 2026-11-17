#pragma once

#include <expected>
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

  /** The builders of a `PlatoonBuilders` text; the error when its Builders table can't be followed. */
  [[nodiscard]] std::expected<std::vector<MissionBuilder>, std::string> ParseBuilders(const std::string& text);

  /** The `PlatoonBuilders` text for these builders (as the saves lay the table out). */
  [[nodiscard]] std::string FormatBuilders(const std::vector<MissionBuilder>& builders);

  /** The top-level items of a Lua table's text (`{ a, 'b', { c } }`), each as written; empty for no table. */
  [[nodiscard]] std::vector<std::string> LuaTableItems(const std::string& table);

  /**
   * A builder's call (FAF Studio's builders editor): `{ '<file>', '<function>', <rest>... }` as PlatoonAIFunction and
   * each of BuildConditions hold it; `rest` the items after the two names, as written, joined by ", ".
   */
  struct BuilderCall
  {
    std::string file;
    std::string function;
    std::string rest;
  };
  bool ParseBuilderCall(const std::string& text, BuilderCall& out);
  [[nodiscard]] std::string FormatBuilderCall(const BuilderCall& call);

  /** A new builder with the fields the game's PBM reads, for a platoon template, at a base's location. */
  [[nodiscard]] MissionBuilder
  NewBuilder(const std::string& name, const std::string& platoonTemplate, const std::string& location);
} // namespace faf::editor
