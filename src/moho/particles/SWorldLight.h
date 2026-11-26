#pragma once

#include <cstdint>

namespace moho
{
  /**
   * FAF addition, not in the shipped binary: one Lua-driven dynamic light, as the sim sends it to the renderer every
   * tick it is alive (docs/DYNAMIC_LIGHTS.md). Visual only: nothing in the simulation reads it. The user side tracks
   * the light by `id`, so a record that keeps coming moves and recolours one light and a record that stops coming lets
   * it fade out.
   */
  struct SWorldLight
  {
    std::uint32_t id = 0; // Lua handle of the light (never 0)
    float pos[3] = {0.0f, 0.0f, 0.0f};
    float dir[3] = {0.0f, 0.0f, 0.0f}; // spotlight: the unit direction it points to, world space
    float rgb[3] = {1.0f, 1.0f, 1.0f};
    float radius = 10.0f;
    float intensity = 1.0f;
    float cone = 0.0f;      // spotlight: cosine of the outer half angle
    std::uint32_t spot = 0; // 1 = spotlight
  };
} // namespace moho
