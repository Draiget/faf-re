#pragma once

#include <string>

#include "editor/doc/EdWater.h"

namespace faf::editor
{
  /**
   * FAForeverMapEditor's water settings file (`.scmwtr`): Unity's JsonUtility dump of its WaterShader
   * (HasWater, Elevation, ElevationDeep, ElevationAbyss, SurfaceColor {x,y,z}, ColorLerp {x,y}, RefractionScale,
   * FresnelBias, FresnelPower, UnitReflection, SkyReflection, SunShininess, SunStrength, SunDirection, SunColor,
   * SunReflection, SunGlow, TexPathCubemap, TexPathWaterRamp, WaveTextures [{TexPath, NormalMovement {x,y},
   * NormalRepeat} x 4]), written the same way.
   */
  std::string WaterToScmwtr(const WaterState& water);

  /** Reads a `.scmwtr` into `water` (every field it has, the levels and texture names included); false with `error`. */
  bool WaterFromScmwtr(const std::string& text, WaterState& water, std::string& error);

  /** The water-motion presets (FAF Studio's): the normal maps' repeat and movement, the rest of the water kept. */
  inline constexpr int kWaterMotionPresetCount = 4;
  [[nodiscard]] const char* WaterMotionPresetName(int preset);
  /**
   * 0 the engine's own (CWaterShaderProperties' defaults, 0x0089F8D0's seed), 1 a calm lake (a quarter of the
   * movement), 2 choppy (two and a half times, finer ripples), 3 an ocean swell (larger, slower waves).
   */
  void ApplyWaterMotionPreset(WaterNumbers& water, int preset);
} // namespace faf::editor
