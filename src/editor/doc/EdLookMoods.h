#pragma once

#include "editor/doc/EdLighting.h"

#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * The looks the editor ships (FAF Studio's library of moods and biomes): a light for a time of day or weather, or a
   * biome's light, laid over the map's own look (its water and sky stay unless a map look is mixed in). Their
   * thumbnails are their colours: the sky (fog), the sun and the shade.
   */
  struct LookMood
  {
    const char* id;
    const char* name;
    const char* group; // "Mood" or "Biome"
    float azimuth;     // degrees, from +x towards +z
    float elevation;   // degrees above the horizon
    float multiplier;
    float sun[3];
    float ambience[3];
    float shadow[3];
    float fog[3];
    float fogStart;
    float fogEnd;
    float bloom;
  };

  [[nodiscard]] const std::vector<LookMood>& LookMoods();
  [[nodiscard]] const LookMood* FindLookMood(const std::string& id);

  /** `base` with the mood's light: sun, ambience, shadow, fog and bloom (specular stays the map's). */
  [[nodiscard]] LightingState MoodLighting(const LookMood& mood, const LightingState& base);
} // namespace faf::editor
