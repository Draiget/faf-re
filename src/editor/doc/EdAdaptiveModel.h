#pragma once

#include <string>
#include <vector>

#include "editor/doc/EdAdaptiveTables.h"
#include "editor/doc/EdGroupOptions.h"

namespace faf::editor
{
  /**
   * An adaptive map's lobby options as a mapper thinks of them (user ask 2026-11-11: the adaptive setup by what the player
   * picks in the lobby, editable in one place): each option the lobby shows or the script reads, what kind it is, and
   * what each of its choices puts on the map. The Adaptive Map window (ui/EdAdaptiveWindow.cpp) draws and edits it.
   */
  struct AdaptiveOption
  {
    enum class Kind
    {
      /** One of the adaptive script's option tables of mass points: value k spawns groups 1 .. k-1 (1 is none). */
      Mexes,
      Hydros,
      /** A level loop of the script (wrecks or units): value v creates the groups `<prefix>from` .. `<prefix>v`. */
      UnitLevels,
      /** Anything else the lobby offers or the script reads (its choices' effects read from the script). */
      Other,
    };
    Kind kind = Kind::Other;
    std::string key;
    /** Index into the parsed `_options.lua` options; -1 when the lobby doesn't offer it. */
    int lobby = -1;
    /** Mexes, Hydros: the table's name (`middleMexes`) and label. */
    std::string table;
    std::string tableLabel;
    /** UnitLevels: the script's loop. */
    ScriptGroupLoop loop;
    /** What the window calls it: the lobby's label, else the table's, else the key made readable. */
    std::string title;
    /** The map's script reads the option (an adaptive script reads every table's option). */
    bool scriptReads = false;
  };

  /**
   * The options in the lobby's order, then the tables and loops the lobby lacks, then other options the script reads.
   * `adaptiveScript`: the map's script reads the tables (AdaptiveTablesPath).
   */
  std::vector<AdaptiveOption> AdaptiveOptionsOf(const std::string& script, const std::vector<LobbyOptionInfo>& lobby, const AdaptiveTables& tables,
                                                bool adaptiveScript);

  /** "Optional naval wreckage" from optional_naval_wreckage. */
  std::string ReadableKey(const std::string& key);

  /** `_options.lua` with the option written back as `option` has it (its keys kept as they are). */
  std::string WithOption(const std::string& optionsText, const LobbyOptionInfo& option);

  /** Mexes, Hydros: the group (0-based) a choice adds, or -1 (the "none" choice). Value key k spawns groups 1 .. k-1. */
  int TableGroupOfChoice(const LobbyOptionInfo::Value& value);
  /** UnitLevels: the group a choice adds (`Optional_Wreckage_3` for key 3), or empty. */
  std::string LoopGroupOfChoice(const ScriptGroupLoop& loop, const LobbyOptionInfo::Value& value);

  /** Other: the groups the script creates with the option at this value (whatever the other options), and as what. */
  struct MadeGroup
  {
    std::string group;
    bool wreck = false;
    bool unit = false;
    bool maybe = false; // also depends on the game (slots, factions)
  };
  std::vector<MadeGroup> GroupsMadeByChoice(const std::string& script, const std::vector<LobbyOptionInfo>& lobby, const std::string& key,
                                            int valueIndex);

  /** A new value for a level option: the next counted key, text "level N". */
  LobbyOptionInfo::Value NextLevelValue(const LobbyOptionInfo& option, const std::string& text);
} // namespace faf::editor
