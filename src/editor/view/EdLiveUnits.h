#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * The running play's units as the editor's view in front of it sees and edits them (user ask 2026-11-11: select, move
   * and change any of the game's units while it plays). Read from the session's user side (the units its interface
   * sees) and the game's UI Lua; changed through the sim's own Lua (`SimLua`, the editor's playback is solo with
   * cheats on), so every change is the game's own: Warp, CreateEnhancement, SetScriptBit, SetHealth, SetVeterancy.
   */
  struct LiveUnit
  {
    std::uint32_t id = 0;
    std::string blueprint;
    float x = 0.0f;
    float y = 0.0f;
    float z = 0.0f;
  };
  /** The play's units now (none between plays). */
  std::vector<LiveUnit> LiveUnits();

  /** One unit's state, read through the game's UI Lua (what its interface shows). */
  struct LiveUnitInfo
  {
    bool found = false;
    std::string blueprint;
    std::string name;
    int army = 0;
    float health = 0.0f;
    float maxHealth = 0.0f;
    int veteran = 0;
    /** The toggles its blueprint has (`RULEUTC_ShieldToggle`...), each on or off. */
    struct Toggle
    {
      std::string cap;
      bool on = false;
    };
    std::vector<Toggle> toggles;
    /** Its blueprint's enhancements (not the `...Remove` ones), its slot, whether it has it, what it needs first. */
    struct Enhancement
    {
      std::string name;
      std::string slot;
      bool has = false;
      std::string prerequisite;
      bool removable = false; // a `<name>Remove` enhancement exists
    };
    std::vector<Enhancement> enhancements;
  };
  LiveUnitInfo ReadLiveUnit(std::uint32_t id);

  /** Runs `lua` in the play's sim with `u` the unit (nothing when it is gone). */
  void LiveUnitDo(std::uint32_t id, const std::string& lua);
  /** The unit warped to (x, z) on the ground. */
  void LiveUnitWarp(std::uint32_t id, float x, float z);

  /** The game's units drawn in the editor's view, or hidden (their meshes culled each frame while hidden). */
  void SetLiveUnitsHidden(bool hidden);

  /** "Shield" for RULEUTC_ShieldToggle. */
  std::string ToggleName(const std::string& cap);
} // namespace faf::editor
