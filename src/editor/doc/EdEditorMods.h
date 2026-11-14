#pragma once

#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * Editor mods (design §8 Assets and mods, after FAF Studio's editor mod API): a mod whose `mod_info.lua` says
   * `editor_mod = true` can add commands to the editor (palette, keys) from `editor/commands.lua`. They are off until
   * the mapper turns one on; each runs in a Lua state of its own with Lua's base library and the `Editor` table only
   * (no files, no engine functions, never the game's sim), and a mod whose command fails is turned off for the session.
   */
  inline constexpr int kEditorApiVersion = 1;
  inline constexpr int kEditorApiOldest = 1;

  struct EditorModInfo
  {
    std::filesystem::path folder;
    std::string name;
    std::string uid;
    std::string description;
    int api = 1; // `editor_api`; missing means 1
    bool editorMod = false;
  };

  /** The top-level `key = value` lines of a mod_info.lua: strings without their quotes, other values as written. */
  [[nodiscard]] std::map<std::string, std::string> ModInfoFields(const std::string& text);
  [[nodiscard]] EditorModInfo ReadEditorModInfo(const std::string& text, const std::filesystem::path& folder);
  /** The editor mods in a mods folder (folders whose mod_info.lua says editor_mod = true), sorted by name. */
  [[nodiscard]] std::vector<EditorModInfo> FindEditorMods(const std::filesystem::path& mods);
  /** Why an editor mod can't run in this editor (its `editor_api`), or "". */
  [[nodiscard]] std::string EditorModIncompatibility(int api);
  /** A command id for a mod's command: `mod.<mod name, letters and digits>.<id>`. */
  [[nodiscard]] std::string EditorModCommandId(const std::string& modName, const std::string& id);

  /** The turned-on mods (uids), kept as a uid a line. */
  [[nodiscard]] std::set<std::string> ParseEnabledMods(const std::string& text);
  [[nodiscard]] std::string SaveEnabledMods(const std::set<std::string>& uids);
} // namespace faf::editor
