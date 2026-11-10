#pragma once

#include <string>
#include <utility>
#include <vector>

#include "moho/sim/WaterBodies.h"

namespace faf::editor
{
  /**
   * One water body of a map as its scenario writes it (`ScenarioInfo.WaterBodies`, docs/WATER_BODIES.md). A field the
   * file leaves out stays out when the editor writes the body back, so the game's defaults still apply to it.
   */
  struct WaterBody
  {
    /** No water: dry ground below a surrounding level (a polder). Needs `fillTo`. */
    bool dry = false;
    bool hasElevation = true;
    float elevation = 0.0f;
    /** The fill takes ground below this; the level when left out. */
    bool hasFillTo = false;
    float fillTo = 0.0f;
    /** Shading levels below the water; the sea's distances below it when left out. */
    bool hasDeep = false;
    float deep = 0.0f;
    bool hasAbyss = false;
    float abyss = 0.0f;
    /** Where the fill starts (world x, z); an outline alone may stand without one. */
    bool hasSeed = true;
    float seedX = 0.0f;
    float seedZ = 0.0f;
    /** A closed curve the fill stays inside: its control points (world x, z), 3 or more. */
    std::vector<std::pair<float, float>> outline;
    /** The fill stays inside height-field vertices [x0, x1] x [z0, z1]. */
    bool hasBounds = false;
    int x0 = 0;
    int z0 = 0;
    int x1 = 0;
    int z1 = 0;
    /**
     * A body the editor couldn't read (an expression, a field of the wrong kind): its text, written back as it was, and
     * why it couldn't be read. Empty for a readable body.
     */
    std::string raw;
    std::string unreadable;

    bool operator==(const WaterBody& other) const = default;
  };

  struct WaterBodiesRead
  {
    std::vector<WaterBody> bodies;
    /** The scenario has a `WaterBodies` table. */
    bool present = false;
    /** The scenario's text doesn't read (no `ScenarioInfo = {...}`, or a broken table); `bodies` is then empty. */
    std::string error;
  };

  /** The water bodies of a `_scenario.lua` text. */
  WaterBodiesRead ReadWaterBodies(const std::string& scenario);

  /** One body as the scenario writes it: `{ Elevation = 30, Seed = { 512, 512 } }`. */
  std::string WaterBodyText(const WaterBody& body);

  /**
   * The scenario with its `WaterBodies` table set to `bodies`: the table replaced where it is, or added at the top of
   * `ScenarioInfo`; taken out when `bodies` is empty. The rest of the text stays as it was.
   */
  std::string WithWaterBodies(const std::string& scenario, const std::vector<WaterBody>& bodies);

  /**
   * The bodies as the game fills them (`STIMap::InstallWaterBodies`, the same defaults and the same skips), with the
   * game's lines for the skipped ones in `log`. `deepBelow` and `abyssBelow` are the sea's distances below its level, or
   * 2.5 and 15 on a map without a sea. `bodyOf`, when given, gets the index in `bodies` of each one returned.
   */
  std::vector<moho::SWaterBodyDesc> WaterBodyDescs(const std::vector<WaterBody>& bodies, float deepBelow, float abyssBelow,
                                                   std::vector<std::string>& log, std::vector<std::size_t>* bodyOf = nullptr);
} // namespace faf::editor
