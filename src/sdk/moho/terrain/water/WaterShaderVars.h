#pragma once

#include "moho/render/d3d/ShaderVar.h"

namespace moho
{
  [[nodiscard]] ShaderVar& GetWater2WorldToViewShaderVar();
  [[nodiscard]] ShaderVar& GetWater2ProjectionShaderVar();
  [[nodiscard]] ShaderVar& GetWater2UtilityTextureCShaderVar();
  [[nodiscard]] ShaderVar& GetWater2ViewPositionShaderVar();
  [[nodiscard]] ShaderVar& GetWater2WaterElevationShaderVar();
  [[nodiscard]] ShaderVar& GetWater2SkyMapShaderVar();
  [[nodiscard]] ShaderVar& GetWater2NormalMap0ShaderVar();
  [[nodiscard]] ShaderVar& GetWater2NormalMap1ShaderVar();
  [[nodiscard]] ShaderVar& GetWater2NormalMap2ShaderVar();
  [[nodiscard]] ShaderVar& GetWater2NormalMap3ShaderVar();
  [[nodiscard]] ShaderVar& GetWater2WaterRampShaderVar();
  [[nodiscard]] ShaderVar& GetWater2RefractionMapShaderVar();
  [[nodiscard]] ShaderVar& GetWater2ReflectionMapShaderVar();
  [[nodiscard]] ShaderVar& GetWater2TimeShaderVar();
  [[nodiscard]] ShaderVar& GetWater2FresnelLookupShaderVar();
  [[nodiscard]] ShaderVar& GetWater2WaterColorShaderVar();
  [[nodiscard]] ShaderVar& GetWater2WaterLerpShaderVar();
  [[nodiscard]] ShaderVar& GetWater2RefractionScaleShaderVar();
  [[nodiscard]] ShaderVar& GetWater2FresnelBiasShaderVar();
  [[nodiscard]] ShaderVar& GetWater2FresnelPowerShaderVar();
  [[nodiscard]] ShaderVar& GetWater2UnitReflectionAmountShaderVar();
  [[nodiscard]] ShaderVar& GetWater2SkyReflectionAmountShaderVar();
  [[nodiscard]] ShaderVar& GetWater2NormalRepeatRateShaderVar();
  [[nodiscard]] ShaderVar& GetWater2Normal1MovementShaderVar();
  [[nodiscard]] ShaderVar& GetWater2Normal2MovementShaderVar();
  [[nodiscard]] ShaderVar& GetWater2Normal3MovementShaderVar();
  [[nodiscard]] ShaderVar& GetWater2Normal4MovementShaderVar();
  [[nodiscard]] ShaderVar& GetWater2SunShininessShaderVar();
  [[nodiscard]] ShaderVar& GetWater2SunReflectionAmountShaderVar();
  [[nodiscard]] ShaderVar& GetWater2SunDirectionShaderVar();
  [[nodiscard]] ShaderVar& GetWater2SunColorShaderVar();
  [[nodiscard]] ShaderVar& GetWater2SunGlowShaderVar();
  [[nodiscard]] ShaderVar& GetWater2TerrainScaleShaderVar();

  /**
   * Address: 0x008111E0 (FUN_008111E0)
   *
   * What it does:
   * Updates the `water2/TerrainScale` shader variable raw pointer lane with a
   * fixed 16-byte payload when the variable exists, then returns that shader
   * variable instance.
   */
  [[nodiscard]] ShaderVar* SetWater2TerrainScaleShaderVarData(const void* terrainScaleData) noexcept;

  [[nodiscard]] ShaderVar& GetWater2WorldToViewShorelineShaderVar();
  [[nodiscard]] ShaderVar& GetWater2ProjectionShorelineShaderVar();
  [[nodiscard]] ShaderVar& GetWater2WaterElevationTShorelineShaderVar();
} // namespace moho
