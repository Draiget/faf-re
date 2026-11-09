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
  };

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

  const char* CheckLevelName(CheckIssue::Level level);
} // namespace faf::editor
