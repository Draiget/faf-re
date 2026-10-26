#pragma once

#include <string>

// Engine addition, server mode (plan WPL.4, WPR.11): `faf-replay --terrain-check <list>`. A
// map without a client loads into the headless terrain resource
// (moho/sim/WldTerrainResHeadless.cpp), which reads the terrain payload of a `.scmap` without
// the renderer's objects. The check loads every map named in <list> (one `.scmap` path per
// line) both ways, with the client's CWldTerrainRes and with the headless resource, and
// compares where the terrain payload ends in the stream, the map data the simulation copies
// (heightfield, terrain-type grid, water) and the props read after it.

namespace faf::replay
{
  struct STerrainCheckResult
  {
    bool ran = false; // false: the list could not be read (see `error`)
    int maps = 0;
    int differences = 0;
    std::string error;
    std::string report; // one line per map, then a summary line
  };

  [[nodiscard]] STerrainCheckResult RunTerrainCheck(const std::string& listPath);
} // namespace faf::replay
