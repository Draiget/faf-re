#pragma once

#include <cstdint>

namespace moho
{
  class Sim;
  class Entity;
} // namespace moho

// The sim-side registry of Lua dynamic lights (docs/DYNAMIC_LIGHTS.md, "Lua lights"). A light is a handle the script
// creates, optionally attaches to a bone of an entity, and later changes or destroys. Every sim tick the registry
// writes one SWorldLight record per live light into the sim particle buffer (SParticleBuffer::mLights); the renderer
// tracks the lights by id. Visual only: nothing here is read by the simulation, nothing is hashed in the sync checksum,
// and the Lua functions behave the same whatever the quality level or the camera: they always return a handle, so
// scripts take the same branches on every client. Lights are not saved with a game.
//
// Sim thread only.
namespace moho::lights
{
  // A new light. With an entity it follows that entity bone (`bone` < 0: the entity's own transform); without one it
  // stays at `world`. Returns the handle (never 0).
  std::uint32_t SimLightCreate(Sim* sim, Entity* entity, int bone, const float (&world)[3]);

  // False when the handle is unknown (destroyed, or its entity died).
  bool SimLightSetColour(Sim* sim, std::uint32_t id, float r, float g, float b, float radius, float intensity);
  bool
  SimLightSetOffset(Sim* sim, std::uint32_t id, float x, float y, float z); // bone-local (or world, without an entity)
  bool SimLightSetPosition(Sim* sim, std::uint32_t id, float x, float y, float z); // world position of a light without
                                                                                   // an entity
  // A spotlight pointing along (dx, dy, dz) in bone space with the given outer half angle in degrees; angle <= 0 makes
  // it a point light again.
  bool SimLightSetSpot(Sim* sim, std::uint32_t id, float dx, float dy, float dz, float coneDegrees);
  bool SimLightDestroy(Sim* sim, std::uint32_t id);

  // Writes this tick records; drops the lights whose entity is gone. Called once per sim tick after the effects ticked.
  void SimLightsTick(Sim* sim);

  // The sim is going away: forget its lights.
  void SimLightsOnSimDestroyed(Sim* sim);

  // Number of live lights of the sim (diagnostics, tests).
  std::uint32_t SimLightCount(Sim* sim);
} // namespace moho::lights
