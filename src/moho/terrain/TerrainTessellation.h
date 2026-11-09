#pragma once

namespace moho
{
  class StratumMaterial;

  /** Engine addition: Direct3D 12 and Vulkan terrain tessellation (terrain_tess.fx); off by default. */
  extern bool ren_TerrainTessellation;

  /**
   * Engine addition (ren_TerrainTessellation).
   *
   * Hands terrain_tess.fx how much relief each ground layer gets (`TerrainTessLayers0..2`: lower,
   * strata 0 to 7), from the layer's albedo file name: rock, sand, dirt, gravel and the like get
   * full relief, grass, moss and other plant layers none (their detail is far finer than the
   * geometry and only smears), anything else half. Called where the strata are bound; a no-op
   * when the terrain effect has no tessellated techniques.
   */
  void TERRAIN_SetTessellationLayers(const StratumMaterial& strata);
} // namespace moho
