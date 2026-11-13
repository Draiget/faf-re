#pragma once

#include <string>

// Source-level patch of FAF's terrain.fx: on a map with water bodies the tint under the water is computed per pixel.
//
// The shipped shader reads the depth of the water from the G channel of the water map (UtilitySamplerC), which is baked
// per 2 x 2 block from one corner height, and tests the pixel against one WaterElevation (the highest level of the map
// when there are bodies). Both are block resolution: the tint showed the 2-unit grid as steps and left a thin line of
// tint on the bank next to a lake below the highest level. With the patch the terrain's UtilityTextureC holds, on such
// a map, the level and abyss of the water of each block (WaterLevelTexel.h) and every read of the depth becomes
// FafWaterDepth(shipped fetch, uv, pixel height): the depth is (level - height) / (level - abyss) at the pixel's own
// height, 0 above the water. `fafWaterLevelParams.x` is 0 on a map without bodies (and when the texture is not bound),
// where FafWaterDepth returns the shipped G channel: the shipped path, with no new sampler.
//
// Pure text in, text out; no engine headers. A source the patch does not recognise is left untouched.
namespace moho::water
{
  struct TerrainWaterLevelPatchResult
  {
    bool patched = false;
    int sites = 0;     // reads of the water map's depth that were replaced
    std::string error; // why nothing was patched, when `patched` is false
  };

  TerrainWaterLevelPatchResult PatchTerrainWaterLevels(std::string& source);
} // namespace moho::water
