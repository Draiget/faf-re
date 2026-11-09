#pragma once

#include <cstring>
#include <string>

#include "moho/terrain/water/CWaterShaderProperties.h"

namespace faf::editor
{
  /**
   * The map's sea as the `.scmap` keeps it: on or off, its level and the deep and abyss levels below it, and the
   * water shader's numbers (colour, reflections, sun, the normal maps' repeat and movement). The textures' names are
   * carried along for the panel to show.
   */
  struct WaterState
  {
    bool enabled = false;
    float elevation = 0.0f;
    float deep = 0.0f;
    float abyss = 0.0f;
    moho::WaterShaderNumericState shader{};
    /** The cubemap, the colour ramp and the four normal maps. */
    std::string textures[6];

    /** The values the editor changes (the textures aren't edited). */
    bool operator==(const WaterState& other) const
    {
      return enabled == other.enabled && elevation == other.elevation && deep == other.deep && abyss == other.abyss &&
             std::memcmp(&shader, &other.shader, sizeof(shader)) == 0;
    }
  };
} // namespace faf::editor
