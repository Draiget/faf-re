#pragma once

// Where the wave simulation takes a source: only over water, at the level of the place. Pure functions with the map's
// lookups passed in, so that the game (STIMap::GetWaterElevationAt, the height field) and the headless lab
// (tools/watersimlab, `gate`) run the same decision.
namespace moho::water
{
  /// The level of a place with no water, as STIMap's GetWaterElevationAt answers there (moho::kWaterBodyNoWater).
  constexpr float kNoWaterLevel = -10000.0f;

  /// Ground within this of the water level counts as land (the margin of the shader's land test).
  constexpr float kLandMargin = 0.1f;

  /// The water level at (x, z) and whether there is any. A map without water bodies has the one level `seaLevel`
  /// everywhere (as before water bodies existed); with them `mapLevelAt(x, z)` is the level of the lake, the polder or
  /// the sea that owns the place, `kNoWaterLevel` for none (a dry body, or the outside of the bodies on a map without a
  /// sea).
  template <class MapLevelAt>
  bool LevelAtPlace(
    const bool hasBodies,
    const float seaLevel,
    MapLevelAt&& mapLevelAt,
    const float x,
    const float z,
    float& level
  )
  {
    if (!hasBodies) {
      level = seaLevel;
      return true;
    }
    const float at = mapLevelAt(x, z);
    if (at == kNoWaterLevel) {
      return false;
    }
    level = at;
    return true;
  }

  /// Whether a source at (x, z) is over water: the place has a level and its ground is below it. The CPU mirror of the
  /// shader's land test (a flash, a glow or a unit ashore, at the height of the sea on a low beach, must not move the
  /// sea; neither must one over a dry polder). `levelAt(x, z, level)` is LevelAtPlace's answer, `groundAt(x, z)` the
  /// height of the ground in world units.
  template <class LevelAt, class GroundAt>
  bool SourceOverWater(
    const float x,
    const float z,
    LevelAt&& levelAt,
    GroundAt&& groundAt
  )
  {
    float level = 0.0f;
    if (!levelAt(x, z, level)) {
      return false;
    }
    return !(groundAt(x, z) > level - kLandMargin);
  }
} // namespace moho::water
