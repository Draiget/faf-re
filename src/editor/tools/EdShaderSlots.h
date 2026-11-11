#pragma once

#include <string>

namespace faf::editor
{
  /**
   * What a texture slot (0 lower, 1-8 strata, 9 upper) holds under a terrain shader, from FAF's effects/terrain.fx
   * layouts: the 0XX, 1XX and 2XX shaders keep stratum 8 (the shader's S7) for map-wide data (water depth, ambient
   * occlusion and shadow in its albedo, the map's normals in its normal) and the upper slot for the layers' height and
   * roughness; Terrain000/050 (and TTerrainXPExt) make the upper slot a macrotexture, Terrain001/051 a specular map;
   * Terrain301 and TerrainPBR keep stratum 8 a stratum (its normal slot: height and roughness) and put the map's
   * normals, water depth and shadow in the upper slot. Empty for an ordinary stratum (and for every slot of the GPG
   * shaders).
   */
  struct ShaderSlotUse
  {
    /** True when the slot holds map-wide data, not a texture that tiles over the ground. */
    bool mapWide = false;
    std::string text;
  };
  ShaderSlotUse ShaderSlotUseOf(const std::string& shader, int slot);

  /**
   * Whether the shader reads a map-wide slot as map-wide data now: terrain.fx switches each on only when the slot's
   * size is above the map's (its tile value under 1: "set the albedo scale bigger than the map size"), else it is a
   * stratum.
   */
  bool MapWideOn(float slotSize, float mapSize);
} // namespace faf::editor
