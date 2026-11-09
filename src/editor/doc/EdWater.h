#pragma once

#include <cstring>
#include <string>

namespace faf::editor
{
  /**
   * The water shader's numbers, as moho::WaterShaderNumericState lays them out (the document copies one into the
   * other; a static_assert there keeps the two the same size). Kept apart so the editor's tests need no engine header.
   */
  struct WaterNumbers
  {
    float mWaterColor[3]{};
    float mWaterLerp[2]{};
    float mRefractionScale{};
    float mFresnelBias{};
    float mFresnelPower{};
    float mUnitReflectionAmount{};
    float mSkyReflectionAmount{};
    float mNormalRepeatRate[4]{};
    float mNormal1Movement[2]{};
    float mNormal2Movement[2]{};
    float mNormal3Movement[2]{};
    float mNormal4Movement[2]{};
    float mSunShininess{};
    float mSunStrength{};
    float mSunDirection[3]{};
    float mSunColor[3]{};
    float mSunReflectionAmount{};
    float mSunGlow{};
  };

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
    WaterNumbers shader{};
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
