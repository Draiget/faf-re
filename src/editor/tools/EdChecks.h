#pragma once

#include <array>
#include <optional>
#include <string>
#include <vector>

#include "editor/doc/EdSaveFile.h"
#include "editor/tools/EdHeightBrush.h"

namespace faf::editor
{
  /** One thing the Check found, at a place on the map. */
  struct CheckIssue
  {
    enum class Level
    {
      Error,   // the game won't play the map as meant
      Warning, // likely a mistake
      Note,    // worth a look
    };
    Level level = Level::Warning;
    /** The marker it is about (or ""). */
    std::string marker;
    std::string text;
    float x = 0.0f;
    float z = 0.0f;
    /** For a script finding: the file (`_script.lua`...) and the line (0 when none). */
    std::string file;
    int line = 0;
    /**
     * A fix the Check offers (FAF Studio's validate.lua): the marker moved to (fixX, fixZ): pulled inside the map or
     * the playable area, or snapped to its build grid.
     */
    enum class Fix
    {
      None,
      PullInside,
      SnapToGrid,
    };
    Fix fix = Fix::None;
    float fixX = 0.0f;
    float fixZ = 0.0f;
  };
  /** A fix's name for its button. */
  const char* CheckFixName(CheckIssue::Fix fix);

  /**
   * Splits a Lua compile error (`[string "x_script.lua"]:12: '=' expected near 'end'`, or `x_script.lua:12: ...`) into
   * its line and message; false when it has no line.
   */
  bool ParseLuaError(const std::string& error, int& line, std::string& message);

  /** What the marker checks look at. */
  struct MarkerCheckInput
  {
    const std::vector<SaveEntry>* markers = nullptr;
    /** The playable area (x0, z0, x1, z1), when the map has one. */
    std::optional<std::array<int, 4>> playable;
    bool water = false;
    float waterLevel = 0.0f;
    /** The height of the ground at (x, z), for the under-water check. */
    float (*groundAt)(const void* context, float x, float z) = nullptr;
    const void* groundContext = nullptr;
    /** The map's symmetry, for the partner check (None skips it). */
    Symmetry symmetry = Symmetry::None;
    int turns = 0;
    /** The height field's size in samples. */
    int width = 0;
    int height = 0;
  };

  /**
   * Checks the start positions and the mass and hydrocarbon points: off the playable area or the map (error), a start
   * under water (warning), a resource under water (note: naval maps have them), without a marker of its type at each
   * of its symmetric copies within 2 units (warning), and two resources whose 2 x 2 extractors would overlap (error).
   */
  std::vector<CheckIssue> CheckMarkers(const MarkerCheckInput& input);

  /** What the map-wide checks look at (FAF Studio's validate.lua): markers, the scenario's armies, chains, names. */
  struct MapBasicsInput
  {
    const std::vector<SaveEntry>* markers = nullptr;
    /** The scenario's team list (its extra armies, like ARMY_9 and NEUTRAL_CIVILIAN, have no start). */
    std::vector<std::string> armies;
    const std::vector<MarkerChain>* chains = nullptr;
    std::string name;
    std::string description;
    /** Prop blueprints the game hasn't got (each with one prop's place): the caller asks the rules. */
    std::vector<std::pair<std::string, std::array<float, 2>>> missingProps;
  };

  /**
   * The map-wide checks: no start position (error) or one (warning); a start the army list hasn't got (warning) and
   * an army without its start (error); no mass point (warning) or fewer than four for each start (note); a resource
   * off the build grid (its extractor's cell middle, x.5: warning); a marker with a broken position (error); a chain
   * naming a marker the map hasn't got (warning); a prop blueprint the game hasn't got (warning, one per blueprint);
   * no name (warning) or description (note).
   */
  std::vector<CheckIssue> CheckMapBasics(const MapBasicsInput& input);

  /** One prop for the symmetry check: its blueprint, place and reclaim mass. */
  struct PropPoint
  {
    std::string blueprint;
    float x = 0.0f;
    float z = 0.0f;
    float mass = 0.0f;
  };

  /**
   * The props' symmetry: a prop with no prop of its blueprint within `reach` of one of its symmetric copies is
   * unmatched (its reclaim isn't the same for every player). Returns a summary (a warning when unmatched props hold
   * mass, else a note; none when all match) and the first `listed` unmatched props, each at its place.
   */
  std::vector<CheckIssue> CheckPropSymmetry(
    const std::vector<PropPoint>& props,
    Symmetry symmetry,
    int turns,
    int width,
    int height,
    float reach = 2.0f,
    std::size_t listed = 20
  );

  const char* CheckLevelName(CheckIssue::Level level);
} // namespace faf::editor
