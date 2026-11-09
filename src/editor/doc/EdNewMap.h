#pragma once

#include <string>
#include <vector>

namespace faf::editor
{
  /** What the New map dialog asks for. */
  struct NewMapSettings
  {
    /** The map's title in the game's lists. */
    std::string title = "New map";
    /** The folder under `<vault>/maps`, FAF's `<name>.v0001` form; its name without the version names the files. */
    std::string folder = "new_map.v0001";
    /** Index into kNewMapSizes. */
    int size = 1;
    /** 1 to 16 start positions, `ARMY_1`... in a ring; `ARMY_17` and `NEUTRAL_CIVILIAN` are added as extra armies. */
    int players = 2;
    bool campaign = false;
    /** The ground's height, in game units. */
    float height = 20.0f;
    bool sea = false;
    /** The sea's level, in game units; its deep and abyss levels are 2.5 and 15 below it. */
    float seaLevel = 17.5f;
  };

  /** The sizes offered: kilometres (as the game's lobby names them) and game units (heights are one more). */
  struct NewMapSize
  {
    const char* name;
    int units;
  };
  inline constexpr NewMapSize kNewMapSizes[] = {{"5 km", 256}, {"10 km", 512}, {"20 km", 1024}, {"40 km", 2048}, {"81 km", 4096}};
  inline constexpr int kNewMapSizeCount = static_cast<int>(sizeof(kNewMapSizes) / sizeof(kNewMapSizes[0]));
  inline constexpr int kNewMapMaxPlayers = 16;

  /** A start position. */
  struct NewMapSpawn
  {
    float x;
    float z;
  };

  /** The start positions: one in the middle, or a ring at 35% of the map's size around it, the first at the top. */
  std::vector<NewMapSpawn> NewMapSpawns(const NewMapSettings& settings);

  /** `<base>_scenario.lua`, as FAF's maps write it (version 3), for the files in `/maps/<folder>/<base>...`. */
  std::string NewMapScenarioText(const NewMapSettings& settings, const std::string& base);

  /** `<base>_save.lua`: the start markers and one army entry for each army, extra armies included. */
  std::string NewMapSaveText(const NewMapSettings& settings);

  /** `<base>_script.lua`: the armies set up, as the game's own maps do. */
  std::string NewMapScriptText();

  /**
   * The `.scmap` preview chunk (RWldMapPreviewChunk's layout, version 2): the map's size, no name or tags,
   * and a 256 x 256 A8R8G8B8 DDS with the classic header: ground green, or sea blue when the ground is
   * under the sea's level, with the start positions as white dots.
   */
  std::vector<char> NewMapPreviewRecord(const NewMapSettings& settings);
} // namespace faf::editor
