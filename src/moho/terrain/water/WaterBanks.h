#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

// Banks of the water bodies, render side (docs/WATER_SIMULATION.md, "Banks"): where a river or a lake meets the ground
// its edge is the true intersection of the water level with the terrain, cut per pixel, not the outline of the water
// map's 2 x 2 blocks. Two parts, both render only (nothing here is read by the sim):
//
//   * the shoreline cut-out mask of a water body is laid by the depth test alone (the water plane is nearer than the
//     terrain), where the shipped mask also needed the block's baked "no shore" flag and the marching-squares polygons
//     of the block (a straight line between the block's corners, two units apart). `PatchWaterBanks` is the source
//     patch of water2.fx, `waterBankParams.x` says that the mask of a body (not the sea) is being drawn;
//   * the mesh of a body reaches the ground: a river's wet vertices stop at its half width and a lake's at its outline
//     or bounds, though the terrain may lie below the level further out, so the plane ended in the air above a pit with
//     a staircase edge. `GrowBanks` takes the pit's vertices in (the ground below the level next to the water, up to a
//     reach, never below the sea or in another body), and the per-pixel cut makes the edge.
//
// No engine types, so the host tests (tests/water/WaterBankTests.cpp) compile it as it is; the cvars, the binding and
// the cache of a map's grown banks are WaterBanksBind.cpp's and WaterBodySurfaces.cpp's.
namespace moho::water
{
  /// The reach of the banks of a body, default and largest: world units past a river's half width, cells from a lake's
  /// water.
  inline constexpr int kBankReachDefault = 8;
  inline constexpr int kBankReachMax = 32;

  struct BankPatchResult
  {
    bool patched = false;
    std::string error;
  };

  /**
   * The source patch of water2.fx for the banks: declares `waterBankParams` and makes `WaterLayAlphaMaskPS` return a
   * cleared mask alpha (wet) for every pixel it is asked about while `waterBankParams.x` is 1. It anchors on lines the
   * other water patches leave alone, so it applies to the shipped text and to the patched text alike, and it is a
   * no-op at run time while `waterBankParams` is all zero. A text that does not carry the anchors exactly once is left
   * untouched.
   */
  BankPatchResult PatchWaterBanks(std::string& source);

  /**
   * The level of the water of `body` at vertex `(x, z)` beside its water, for `GrowBanks`: a river's level field
   * carried on past its support (the level of the nearest point of the centreline), a lake's level; false where the
   * vertex is further from the body than the reach allows. `ring` is the number of the ring being made (0 the
   * neighbours of the water). `context` is the caller's.
   */
  using BankLevelFn = bool (*)(const void* context, std::uint8_t body, int x, int z, int ring, float& level);

  /**
   * Grows the water of the rivers and lakes of a map over the pits beside them. The map is `width` x `height` vertices;
   * `terrain` holds their heights (world units), `body` the body of each vertex as the sim has it (0 none or the sea),
   * and `grows[b]` says whether body `b` grows (a river or a lake with water, not a dry body). A vertex with no body
   * whose terrain lies below the level `levelAt` gives for a neighbouring vertex's body, and is not below `seaLevel`
   * (the sea has it), joins that body with that level, ring by ring (four-neighbour steps, so it stays connected to the
   * water), at most `rings` rings. When two bodies reach a vertex in the same ring the lower body number gets it; of
   * one body's levels the lowest does.
   *
   * The result goes to `grownBody` and `grownLevel` (`width * height` entries each, written whole): the body of a
   * grown vertex, else 0, and its level. Returns the number of grown vertices. `body` is not changed.
   */
  std::size_t GrowBanks(
    int width,
    int height,
    const float* terrain,
    const std::uint8_t* body,
    const bool (&grows)[256],
    float seaLevel,
    int rings,
    BankLevelFn levelAt,
    const void* context,
    std::uint8_t* grownBody,
    float* grownLevel
  );
} // namespace moho::water
