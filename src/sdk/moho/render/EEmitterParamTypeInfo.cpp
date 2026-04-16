#include "moho/render/EEmitterParamTypeInfo.h"

#include <cstdint>
#include <typeinfo>

#include "moho/render/EEmitterParam.h"

using namespace moho;

/**
 * Address: 0x00770790 (FUN_00770790)
 *
 * What it does:
 * Preregisters the reflected `EEmitterParam` enum metadata.
 */
EEmitterParamTypeInfo::EEmitterParamTypeInfo()
{
  gpg::PreRegisterRType(typeid(EEmitterParam), this);
}

/**
 * Address: 0x00770820 (FUN_00770820, scalar deleting thunk)
 */
EEmitterParamTypeInfo::~EEmitterParamTypeInfo() = default;

/**
 * Address: 0x00770810 (FUN_00770810)
 *
 * What it does:
 * Returns the reflection type name literal for EEmitterParam.
 */
const char* EEmitterParamTypeInfo::GetName() const
{
  return "EEmitterParam";
}

/**
 * Address: 0x00770850 (FUN_00770850)
 *
 * What it does:
 * Registers EEmitterParam enum option names/values.
 */
void EEmitterParamTypeInfo::AddEnums()
{
  mPrefix = "EFFECT_";
  AddEnum(StripPrefix("EFFECT_POSITION"), static_cast<std::int32_t>(EFFECT_POSITION));
  AddEnum(StripPrefix("EFFECT_POSITION_X"), static_cast<std::int32_t>(EFFECT_POSITION_X));
  AddEnum(StripPrefix("EFFECT_POSITION_Y"), static_cast<std::int32_t>(EFFECT_POSITION_Y));
  AddEnum(StripPrefix("EFFECT_POSITION_Z"), static_cast<std::int32_t>(EFFECT_POSITION_Z));
  AddEnum(StripPrefix("EFFECT_TICKCOUNT"), static_cast<std::int32_t>(EFFECT_TICKCOUNT));
  AddEnum(StripPrefix("EFFECT_LIFETIME"), static_cast<std::int32_t>(EFFECT_LIFETIME));
  AddEnum(StripPrefix("EFFECT_REPEATTIME"), static_cast<std::int32_t>(EFFECT_REPEATTIME));
  AddEnum(StripPrefix("EFFECT_TICKINCREMENT"), static_cast<std::int32_t>(EFFECT_TICKINCREMENT));
  AddEnum(StripPrefix("EFFECT_BLENDMODE"), static_cast<std::int32_t>(EFFECT_BLENDMODE));
  AddEnum(StripPrefix("EFFECT_FRAMECOUNT"), static_cast<std::int32_t>(EFFECT_FRAMECOUNT));
  AddEnum(StripPrefix("EFFECT_USE_LOCAL_VELOCITY"), static_cast<std::int32_t>(EFFECT_USE_LOCAL_VELOCITY));
  AddEnum(StripPrefix("EFFECT_USE_LOCAL_ACCELERATION"), static_cast<std::int32_t>(EFFECT_USE_LOCAL_ACCELERATION));
  AddEnum(StripPrefix("EFFECT_USE_GRAVITY"), static_cast<std::int32_t>(EFFECT_USE_GRAVITY));
  AddEnum(StripPrefix("EFFECT_ALIGN_ROTATION"), static_cast<std::int32_t>(EFFECT_ALIGN_ROTATION));
  AddEnum(StripPrefix("EFFECT_INTERPOLATE_EMISSION"), static_cast<std::int32_t>(EFFECT_INTERPOLATE_EMISSION));
  AddEnum(StripPrefix("EFFECT_TEXTURE_STRIPCOUNT"), static_cast<std::int32_t>(EFFECT_TEXTURE_STRIPCOUNT));
  AddEnum(StripPrefix("EFFECT_ALIGN_TO_BONE"), static_cast<std::int32_t>(EFFECT_ALIGN_TO_BONE));
  AddEnum(StripPrefix("EFFECT_SORTORDER"), static_cast<std::int32_t>(EFFECT_SORTORDER));
  AddEnum(StripPrefix("EFFECT_FLAT"), static_cast<std::int32_t>(EFFECT_FLAT));
  AddEnum(StripPrefix("EFFECT_SCALE"), static_cast<std::int32_t>(EFFECT_SCALE));
  AddEnum(StripPrefix("EFFECT_LODCUTOFF"), static_cast<std::int32_t>(EFFECT_LODCUTOFF));
  AddEnum(StripPrefix("EFFECT_EMITIFVISIBLE"), static_cast<std::int32_t>(EFFECT_EMITIFVISIBLE));
  AddEnum(StripPrefix("EFFECT_CATCHUPEMIT"), static_cast<std::int32_t>(EFFECT_CATCHUPEMIT));
  AddEnum(StripPrefix("EFFECT_CREATEIFVISIBLE"), static_cast<std::int32_t>(EFFECT_CREATEIFVISIBLE));
  AddEnum(StripPrefix("EFFECT_SNAPTOWATERLINE"), static_cast<std::int32_t>(EFFECT_SNAPTOWATERLINE));
  AddEnum(StripPrefix("EFFECT_ONLYEMITONWATER"), static_cast<std::int32_t>(EFFECT_ONLYEMITONWATER));
  AddEnum(StripPrefix("EFFECT_PARTICLERESISTANCE"), static_cast<std::int32_t>(EFFECT_PARTICLERESISTANCE));
  AddEnum(StripPrefix("EFFECT_LASTPARAM"), static_cast<std::int32_t>(EFFECT_LASTPARAM));
}

/**
 * Address: 0x007707F0 (FUN_007707F0)
 *
 * What it does:
 * Writes enum width, registers enum values, then finalizes metadata.
 */
void EEmitterParamTypeInfo::Init()
{
  size_ = sizeof(EEmitterParam);
  gpg::RType::Init();
  AddEnums();
  Finish();
}
