#pragma once

#include <string_view>

#include "moho/render/lights/LightTexture.h"

// How much a unit mesh glows, and in which colour, read from its textures the way its pixel shader reads them
// (mesh.fx):
//
//   shader     emission (per texel)                                                   team colour
//   Unit       specular.b * 0.8                                                         from specular.a (the mask), not
//   part of the glow Aeon       specular.b + specular.a * teamColour * 0.5                               the specular.a
//   share of the glow is the team colour AeonCZAR   as Aeon Insect     sqrt(max(specular.b - 0.04, 0)) - Seraphim
//   saturate(specular.b - 0.1) + albedo.a * teamColour + saturate(albedo.rgb - 0.4) * 1.5   the albedo.a share is the
//   team colour *Glow*     emission = max(albedo.rgb): a projectile or effect mesh that glows as a whole Nuke* emission
//   = 1: the fireball mesh of a strategic missile (NukeUEF, NukeEMP, NukeQuantum) burns as a whole *Build*    emission
//   = 0.25, in the faction's build colour (a unit being built: the scan effect) ShieldImpact emission = 0.5: the flash
//   of a hit on a shield others     no glow: props, wreckage (its specular.b is noise), shield bubbles, the map border
//
// (the channels: specular.r metal, .g roughness, .b glow, .a team mask; for the Seraphim the team mask is the albedo
// alpha). The glow colour of a texel is its albedo, except where the team colour is the source. Pure functions on
// decoded images (LightTexture.h), no engine headers.
namespace moho::lights
{
  struct MeshGlow
  {
    bool valid = false;
    float area = 0.0f; // mean emission over the texture, 0..~1.5: how much of the surface glows, and how hard
    float hue[3] = {1.0f, 1.0f, 1.0f}; // colour of the glow that is not team colour, brightest channel = 1
    float teamShare = 0.0f; // 0..1: the part of the glow that is the army colour (the caller multiplies it with the
                            // instance's team colour)
    bool effect = false; // an effect mesh that is a light by itself (nuke fireball, shield impact): its light may reach
                         // further than a unit's
    bool nuke = false;   // the fireball of a strategic missile detonation
  };

  // `albedo` is required, `specular` may be null (a mesh without a specular map has no glow except the Seraphim albedo
  // rule). The two images may have different sizes; they are compared by normalised texture coordinate. `shader` is
  // RMeshBlueprintLOD::mShaderName.
  MeshGlow AnalyseMeshGlow(const Rgba8Image& albedo, const Rgba8Image* specular, std::string_view shader);

  // The strength of the light a glow of this size makes: how much light the unit puts on its surroundings,
  // 0..kMaxMeshIntensity.
  constexpr float kMaxMeshIntensity =
    0.85f; // was 0.8: a Seraphim structure with bright panels lit a white halo wider than itself
  constexpr float kMaxNukeMeshIntensity = 1.2f; // the fireball of a nuke is the brightest light there is
  constexpr float kMaxUnitLightRadius = 60.0f;
  constexpr float kMaxEffectLightRadius = 150.0f; // a nuke fireball is tens of units across
  constexpr float kMinMeshGlowArea = 0.002f;
  float MeshLightIntensity(const MeshGlow& glow);

  // Its radius, from the radius of the unit's bounding sphere: the glow reaches about one and a half body sizes, never
  // less than 2 units.
  float MeshLightRadius(float sphereRadius, float maxRadius = kMaxUnitLightRadius);
} // namespace moho::lights
