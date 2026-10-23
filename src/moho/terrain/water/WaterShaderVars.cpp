#include "moho/terrain/water/WaterShaderVars.h"
#include "gpg/gal/EffectVariable.hpp"

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
  /*
   * The spellings below are the binary's, byte for byte: the CRT-init thunks
   * 0x00BE3520..0x00BE36C0 pass "waterColor" (0x00E41CB8) through
   * "sunReflectionAmount" (0x00E41D8C) to RegisterShaderVar (0x00438000), and
   * effects/water2.fx declares them the same way. Effect parameter lookup is
   * case-sensitive, so the capitalised forms a previous pass guessed never
   * bound and every one of these read the shader's compiled-in default.
   * SunShininess and SunGlow really are capitalised (0x00BE36A0, 0x00BE36E0).
   */
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2WaterColorShaderVar, "waterColor")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2WaterLerpShaderVar, "waterLerp")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2RefractionScaleShaderVar, "refractionScale")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2FresnelBiasShaderVar, "fresnelBias")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2FresnelPowerShaderVar, "fresnelPower")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2UnitReflectionAmountShaderVar, "unitreflectionAmount")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2SkyReflectionAmountShaderVar, "skyreflectionAmount")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2NormalRepeatRateShaderVar, "normalRepeatRate")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2Normal1MovementShaderVar, "normal1Movement")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2Normal2MovementShaderVar, "normal2Movement")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2Normal3MovementShaderVar, "normal3Movement")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2Normal4MovementShaderVar, "normal4Movement")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2SunShininessShaderVar, "SunShininess")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2SunReflectionAmountShaderVar, "sunReflectionAmount")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2SunDirectionShaderVar, "SunDirection")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2SunColorShaderVar, "SunColor")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2SunGlowShaderVar, "SunGlow")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2TerrainScaleShaderVar, "TerrainScale")

  /**
   * Address: 0x008111E0 (FUN_008111E0)
   *
   * What it does:
   * Writes one 16-byte raw payload into `water2/TerrainScale` when that
   * shader variable exists, then returns the variable lane.
   */
  ShaderVar* SetWater2TerrainScaleShaderVarData(const void* const terrainScaleData) noexcept
  {
    ShaderVar& shaderVar = GetWater2TerrainScaleShaderVar();
    if (shaderVar.Exists()) {
      shaderVar.mEffectVariable->SetValue(terrainScaleData, 16U);
    }
    return &shaderVar;
  }

  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2ViewportScaleOffsetShaderVar, "ViewportScaleOffset")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2WorldToViewShorelineShaderVar, "WorldToView")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2ProjectionShorelineShaderVar, "Projection")
  DEFINE_WATER2_SHADER_VAR_GETTER(GetWater2WaterElevationTShorelineShaderVar, "WaterElevation")
} // namespace moho

#undef DEFINE_WATER2_SHADER_VAR_GETTER
