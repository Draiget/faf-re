#pragma once

#include "editor/terrain/EdFieldCore.h"
#include "editor/tools/EdChecks.h"

#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * The terrain checks (FAF Studio's terrainchecks.lua) the map check runs besides its marker and pathing checks: the
   * ground of every start position (too much steep ground for land units in its base area) and under every resource
   * marker (more variation than a structure takes), and the route length between the starts over the passable ground
   * (a long detour against the straight distance). On the field library's slope, regions and reach ops.
   */
  struct TerrainCheckSettings
  {
    float limit = 0.75f;        // the slope rating that blocks land units
    int window = 2;             // the unit footprint in cells (2: a medium land unit)
    float startRadius = 10.0f;  // the base area around a start
    float blockedShare = 0.04f; // more of it blocked than this is reported
    float detour = 3.0f;        // a route longer than this many times the straight distance is reported
    float wade = 0.5f;          // land units cross water up to this deep
  };

  struct TerrainCheckPoint
  {
    std::string name;
    float x = 0.0f;
    float z = 0.0f;
  };

  /** The base areas and the ground under the resources. `heights`: the map's heights in units, a sample per unit. */
  [[nodiscard]] std::vector<CheckIssue> CheckTerrainGround(
    const field::Grid& heights,
    const std::vector<TerrainCheckPoint>& starts,
    const std::vector<TerrainCheckPoint>& resources,
    const TerrainCheckSettings& settings
  );

  /**
   * The route from the first start to each other start that shares its ground, over the ground land units can cross
   * (`water`: the sea level, or below the lowest ground for none): a note with its length, a warning when it is a long
   * detour.
   */
  [[nodiscard]] std::vector<CheckIssue> CheckTerrainRoutes(
    const field::Grid& heights,
    float water,
    const std::vector<TerrainCheckPoint>& starts,
    const TerrainCheckSettings& settings
  );
} // namespace faf::editor
