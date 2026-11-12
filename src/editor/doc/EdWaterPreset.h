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
} // namespace faf::editor
