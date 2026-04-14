#include "moho/terrain/water/WaterShaderVars.h"

namespace
{
#define DEFINE_WATER2_SHADER_VAR_GETTER(FUNC_NAME, VARIABLE_NAME) \
  [[nodiscard]] moho::ShaderVar& FUNC_NAME() \
  { \
    static moho::ShaderVar shaderVar{}; \
    static const bool registered = (moho::RegisterShaderVar(VARIABLE_NAME, &shaderVar, "water2"), true); \
    (void)registered; \
    return shaderVar; \
  }
} // namespace

namespace moho
{
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2WorldToViewShaderVar, "WorldToView")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2ProjectionShaderVar, "Projection")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2UtilityTextureCShaderVar, "UtilityTextureC")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2ViewPositionShaderVar, "ViewPosition")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2WaterElevationShaderVar, "WaterElevation")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2SkyMapShaderVar, "SkyMap")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2NormalMap0ShaderVar, "NormalMap0")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2NormalMap1ShaderVar, "NormalMap1")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2NormalMap2ShaderVar, "NormalMap2")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2NormalMap3ShaderVar, "NormalMap3")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2WaterRampShaderVar, "WaterRamp")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2RefractionMapShaderVar, "RefractionMap")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2ReflectionMapShaderVar, "ReflectionMap")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2TimeShaderVar, "Time")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2FresnelLookupShaderVar, "FresnelLookup")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2WaterColorShaderVar, "WaterColor")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2WaterLerpShaderVar, "WaterLerp")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2RefractionScaleShaderVar, "RefractionScale")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2FresnelBiasShaderVar, "FresnelBias")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2FresnelPowerShaderVar, "FresnelPower")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2UnitReflectionAmountShaderVar, "UnitReflectionAmount")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2SkyReflectionAmountShaderVar, "SkyReflectionAmount")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2NormalRepeatRateShaderVar, "NormalRepeatRate")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2Normal1MovementShaderVar, "Normal1Movement")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2Normal2MovementShaderVar, "Normal2Movement")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2Normal3MovementShaderVar, "Normal3Movement")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2Normal4MovementShaderVar, "Normal4Movement")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2SunShininessShaderVar, "SunShininess")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2SunReflectionAmountShaderVar, "SunReflectionAmount")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2SunDirectionShaderVar, "SunDirection")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2SunColorShaderVar, "SunColor")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2SunGlowShaderVar, "SunGlow")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2TerrainScaleShaderVar, "TerrainScale")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2WorldToViewShorelineShaderVar, "WorldToView")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2ProjectionShorelineShaderVar, "Projection")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2WaterElevationTShorelineShaderVar, "WaterElevation")
} // namespace moho

#undef DEFINE_WATER2_SHADER_VAR_GETTER
