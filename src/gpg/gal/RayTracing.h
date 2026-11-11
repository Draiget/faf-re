#pragma once

// FAF addition, not in the shipped binary.
//
// Engine addition (`ren_RayTracedShadows`): a ray-traced copy of the world's opaque geometry on Direct3D 12
// (DXR 1.1 inline ray queries) and Vulkan (VK_KHR_ray_query). The renderer hands the backend each piece of
// geometry once (a terrain tile, the triangles of one mesh bone) and, every frame, the list of placed pieces;
// the backend keeps one bottom-level structure per piece and rebuilds the top-level one from the list before
// the next draw that reads it.
//
// The lighting shaders read it through the shadow lookups the effect layer already routes (ShadowCascades.h):
// with rays on, a point the shader asks the shadow map about is also tested by a ray towards the sun, and a
// ray that hits something shades the point.

#include <atomic>
#include <cstdint>

#include "boost/shared_ptr.h"

namespace gpg::gal
{
  class Texture;

  /** Handle of one piece of ray geometry; 0 is none. */
  using RayGeometryId = std::uint32_t;

  /** Triangles of one piece, in the piece's own space. */
  struct RayGeometryDesc
  {
    const char* name = "";
    const float* positions = nullptr; ///< x, y, z of each vertex, `positionStride` bytes apart
    std::uint32_t positionStride = 12U;
    std::uint32_t vertexCount = 0U;
    const std::uint32_t* indices = nullptr; ///< three per triangle
    std::uint32_t indexCount = 0U;
    /**
     * Engine addition (ren_RayAlphaShadows): texture coordinates, u and v per vertex `uvStride` bytes apart, for a
     * piece whose surface is cut out by its texture's alpha (mesh.fx's DepthClip: alpha under 0.5 is a hole). Such a
     * piece is not opaque: a ray that meets it asks its instance's texture whether the point is solid.
     */
    const float* uvs = nullptr;
    std::uint32_t uvStride = 8U;
  };

  /** Engine addition (ren_RayAlphaShadows): the most textures one frame's alpha-tested instances can use. */
  inline constexpr std::uint32_t kRayTextureSlots = 64U;

  /**
   * Bumped whenever a device creates or releases its ray objects: geometry ids handed out before belong to
   * objects that are gone (a new device may sit at the old one's address and reuse the ids).
   */
  inline std::atomic<std::uint64_t> gRaySceneEpoch{0U};

  /**
   * Instance mask bits: what a ray can ask to see. The shadow lookups (ModernHlsl.cpp's kRayShadowHelpers) use
   * the values 1 and 2 as literals.
   */
  enum RayMask : std::uint8_t
  {
    kRayMaskTerrain = 1U << 0U,
    kRayMaskMesh = 1U << 1U,
  };

  /** One placed piece: a row-major 3x4 transform from the piece's space to world space. */
  struct RayInstance
  {
    float transform[3][4]{};
    RayGeometryId geometry = 0U;
    std::uint8_t mask = kRayMaskMesh;
    /**
     * For a piece made with `uvs`: 1 + the index of its texture in SetRayInstances's `textures` (the alpha
     * decides where rays pass); 0 for an opaque piece.
     */
    std::uint32_t texture = 0U;
  };
} // namespace gpg::gal
