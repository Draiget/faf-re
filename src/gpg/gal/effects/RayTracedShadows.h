#pragma once

// FAF addition, not in the shipped binary.
//
// Engine addition (`ren_RayTracedShadows`): sun shadows by ray, on Direct3D 12 and Vulkan devices with inline
// ray queries (gal/RayTracing.h holds the scene).
//
// FAF's mesh.fx and terrain.fx read the shadow map through the lookups ShadowCascades.h routes. Each call
// site passes `<coords>.xy`, where `<coords>` is the point's whole shadow coordinate (u, v, light depth z), so
// the effect layer adds `<coords>` as a third argument. From it the lookup gets the point in world space
// (the inverse of the shadow camera's matrix, published here) and casts one ray towards the sun:
//  - mesh.fx compares z with the texel's red channel, so a blocked ray returns a red far below any depth;
//  - terrain.fx multiplies by the green channel ("1 where sun is"), so a blocked ray returns green 0.
// terrain.fx moves its z 0.01 towards the light before the lookup and mesh.fx doesn't, so the point is rebuilt
// for the channel the call site reads (the effect layer looks past the call): a red reading from z, a green one
// from z + 0.01 (kRayShadowHelpers in ModernHlsl.cpp). Meshes and the ground are traced apart: the drawn ground
// is coarser than the traced height field far from the camera, so a ground point's ray counts the traced ground
// only past a distance that grows with camera distance. In this mode the shadow map keeps only what the scene
// lacks (alpha-tested meshes such as trees), so the texel still adds those.

#include <cstdint>
#include <string_view>

namespace gpg::gal::effects
{
  /**
   * float4s in `faf_RayShadows`:
   * [0..3] rows of the inverse of the shadow camera's view-projection (clip (x, y, z, 1) times it is world);
   * [4] (1 when rays are on, else 0; mesh bias; ground bias; the ground's bias against the traced ground per
   *     unit of camera distance);
   * [5] (camera position x, y, z; longest ray);
   * [6] (direction towards the sun x, y, z, unit length; ren_RayShadowDebug);
   * [7] (the ground's bias against the traced ground along a shadow ray, world units; how far straight down
   *     the traced ground's spacing and terrain tessellation's sinking can put a drawn point under it, which
   *     ren_RayAo reads; tangent of the sun's angular radius, 0 for hard shadows (ren_RaySunAngle); rays per
   *     ground point over the sun's disc (ren_RaySoftRays)).
   */
  // [8]: ren_RayWaterReflections - 1 when the water traces its reflections, their reach in world units.
  inline constexpr std::uint32_t kRayShadowVectors = 9U;
  inline constexpr std::string_view kRayShadowParameter = "faf_RayShadows";

  struct RayShadowConstants
  {
    float vectors[kRayShadowVectors][4]{};
    std::uint64_t version = 0U;
  };

  /** Written by the shadow renderer once per frame before the lit passes; read by the backends' BindPass. */
  extern RayShadowConstants gRayShadows;

  /**
   * Set by a Direct3D 12 or Vulkan device that has inline ray queries, when it is created (false for every
   * other device): the effect layer then gives the shadow lookups their ray code.
   */
  extern bool gRayQueryShaders;

  /** ren_RayTracedShadows: 1 on where the device can, 0 off (live), -1 the devices don't look (at creation). */
  extern int gRayTracedShadows;

  [[nodiscard]] inline bool RayTracedShadowsWanted() noexcept
  {
    return gRayTracedShadows >= 0;
  }

  /** The declaration the effect layer adds, with the cascade one, when the device traces rays. */
  [[nodiscard]] std::string_view RayShadowDeclaration() noexcept;
} // namespace gpg::gal::effects
