#pragma once

#include <string>

// Source-level patch of FAF's water2.fx (docs/WATER_REFLECTIONS.md): what the water pixel shader shows of the scene
// around it.
//
//   - screen-space reflections: the reflected view ray is marched through a copy of the scene depth and, where it goes
//   behind what the scene
//     drew, the pixel of the scene colour the refraction already holds is the reflection (terrain, buildings, trees and
//     units show in the water);
//   - thickness: the tint, the refraction strength and the rejection of what is in front of the water follow the
//   distance the view ray really
//     travels through the water (the depth of the scene under the surface pixel) instead of the map's baked half
//     resolution depth map;
//   - caustics on the sea bed, from the wave simulation's slope and curvature when the simulation patch is in the
//   shader;
//   - the sheen: a physical Fresnel term and a sky reflection tinted toward the water's own colour;
//   - the sun shadow map darkening the water under units, buildings and trees.
//
// Everything reads the surface pixel's own world position (ViewPosition - mViewVec) and the scene depth under it, never
// a single sea level, so it is right on every level of a map with water bodies: each level's mesh puts its vertices at
// the WaterElevation of its draw.
//
// Pure text in, text out; no engine headers. All behaviour is switched by effect parameters the engine binds every
// frame (WaterReflections.cpp): waterSsrParams, waterSsrParams2, waterAbsorbParams, waterShadowParams (all zero = the
// shipped look). A source the patch does not recognise (a FAF update that changed the shader) is left untouched and
// `error` says why.
namespace moho::water
{
  struct ReflectionPatchResult
  {
    bool patched = false;
    std::string error; // why nothing was patched, when `patched` is false
  };

  ReflectionPatchResult PatchWaterReflections(std::string& source);
} // namespace moho::water
