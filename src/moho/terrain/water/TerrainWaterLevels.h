#pragma once

namespace moho
{
  class IWldTerrainRes;
  struct ShaderVar;
} // namespace moho

// Engine side of TerrainWaterLevelPatch.h: what the terrain effect's UtilityTextureC holds. On a map with water bodies,
// and while the patched effect is the one in use, it is the terrain's water level map (one texel per block with the
// level and abyss of its water) and `fafWaterLevelParams` says so; otherwise it is the water map, as shipped.
namespace moho::water
{
  // Set by the effect loader: terrain.fx was built with the patch (FafWaterDepth exists).
  void SetTerrainWaterLevelsPatched(bool patched);
  [[nodiscard]] bool TerrainWaterLevelsPatched();

  // True when the environment variable FAF_NO_RENDER_ADDITIONS is 1: the effect loader then leaves terrain.fx alone.
  [[nodiscard]] bool TerrainWaterLevelsAdditionsDisabled();

  // True while the effect loader should patch terrain.fx: the map being drawn has water bodies (and
  // ren_TerrainWaterLevels is on). A map without bodies keeps the shipped effect text, so its frames are the shipped
  // ones.
  [[nodiscard]] bool TerrainWaterLevelsWanted();

  // Each frame, before anything is drawn: when what the effect should be (patched or not, TerrainWaterLevelsWanted) has
  // changed since it was built, rebuilds terrain.fx. True when it did; the caller makes the terrain renderers again, as
  // after the light live switch (they set their variables once).
  bool ApplyTerrainWaterLevelsLive();

  // Binds UtilityTextureC of the terrain effect (called where the shipped code bound the water map) and sets
  // fafWaterLevelParams.
  void BindTerrainWaterMap(IWldTerrainRes& terrainRes, ShaderVar& utilityTextureC);
} // namespace moho::water
