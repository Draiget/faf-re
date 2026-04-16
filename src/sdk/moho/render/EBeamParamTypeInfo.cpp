#include "moho/render/EBeamParamTypeInfo.h"

#include <cstdint>
#include <typeinfo>

#include "moho/render/EBeamParam.h"

using namespace moho;

/**
 * Address: 0x00770AC0 (FUN_00770AC0)
 *
 * What it does:
 * Preregisters the reflected `EBeamParam` enum metadata.
 */
EBeamParamTypeInfo::EBeamParamTypeInfo()
{
  gpg::PreRegisterRType(typeid(EBeamParam), this);
}

/**
 * Address: 0x00770B50 (FUN_00770B50, scalar deleting thunk)
 */
EBeamParamTypeInfo::~EBeamParamTypeInfo() = default;

/**
 * Address: 0x00770B40 (FUN_00770B40)
 *
 * What it does:
 * Returns the reflection type name literal for EBeamParam.
 */
const char* EBeamParamTypeInfo::GetName() const
{
  return "EBeamParam";
}

/**
 * Address: 0x00770B80 (FUN_00770B80)
 *
 * What it does:
 * Registers EBeamParam enum option names/values.
 */
void EBeamParamTypeInfo::AddEnums()
{
  mPrefix = "BEAM_";
  AddEnum(StripPrefix("BEAM_POSITION"), static_cast<std::int32_t>(BEAM_POSITION));
  AddEnum(StripPrefix("BEAM_POSITION_X"), static_cast<std::int32_t>(BEAM_POSITION_X));
  AddEnum(StripPrefix("BEAM_POSITION_Y"), static_cast<std::int32_t>(BEAM_POSITION_Y));
  AddEnum(StripPrefix("BEAM_POSITION_Z"), static_cast<std::int32_t>(BEAM_POSITION_Z));
  AddEnum(StripPrefix("BEAM_ENDPOSITION"), static_cast<std::int32_t>(BEAM_ENDPOSITION));
  AddEnum(StripPrefix("BEAM_ENDPOSITION_X"), static_cast<std::int32_t>(BEAM_ENDPOSITION_X));
  AddEnum(StripPrefix("BEAM_ENDPOSITION_Y"), static_cast<std::int32_t>(BEAM_ENDPOSITION_Y));
  AddEnum(StripPrefix("BEAM_ENDPOSITION_Z"), static_cast<std::int32_t>(BEAM_ENDPOSITION_Z));
  AddEnum(StripPrefix("BEAM_LENGTH"), static_cast<std::int32_t>(BEAM_LENGTH));
  AddEnum(StripPrefix("BEAM_LIFETIME"), static_cast<std::int32_t>(BEAM_LIFETIME));
  AddEnum(StripPrefix("BEAM_STARTCOLOR"), static_cast<std::int32_t>(BEAM_STARTCOLOR));
  AddEnum(StripPrefix("BEAM_STARTCOLOR_R"), static_cast<std::int32_t>(BEAM_STARTCOLOR_R));
  AddEnum(StripPrefix("BEAM_STARTCOLOR_G"), static_cast<std::int32_t>(BEAM_STARTCOLOR_G));
  AddEnum(StripPrefix("BEAM_STARTCOLOR_B"), static_cast<std::int32_t>(BEAM_STARTCOLOR_B));
  AddEnum(StripPrefix("BEAM_STARTCOLOR_A"), static_cast<std::int32_t>(BEAM_STARTCOLOR_A));
  AddEnum(StripPrefix("BEAM_ENDCOLOR"), static_cast<std::int32_t>(BEAM_ENDCOLOR));
  AddEnum(StripPrefix("BEAM_ENDCOLOR_R"), static_cast<std::int32_t>(BEAM_ENDCOLOR_R));
  AddEnum(StripPrefix("BEAM_ENDCOLOR_G"), static_cast<std::int32_t>(BEAM_ENDCOLOR_G));
  AddEnum(StripPrefix("BEAM_ENDCOLOR_B"), static_cast<std::int32_t>(BEAM_ENDCOLOR_B));
  AddEnum(StripPrefix("BEAM_ENDCOLOR_A"), static_cast<std::int32_t>(BEAM_ENDCOLOR_A));
  AddEnum(StripPrefix("BEAM_THICKNESS"), static_cast<std::int32_t>(BEAM_THICKNESS));
  AddEnum(StripPrefix("BEAM_USHIFT"), static_cast<std::int32_t>(BEAM_USHIFT));
  AddEnum(StripPrefix("BEAM_VSHIFT"), static_cast<std::int32_t>(BEAM_VSHIFT));
  AddEnum(StripPrefix("BEAM_REPEATRATE"), static_cast<std::int32_t>(BEAM_REPEATRATE));
  AddEnum(StripPrefix("BEAM_LODCUTOFF"), static_cast<std::int32_t>(BEAM_LODCUTOFF));
  AddEnum(StripPrefix("BEAM_LASTPARAM"), static_cast<std::int32_t>(BEAM_LASTPARAM));
}

/**
 * Address: 0x00770B20 (FUN_00770B20)
 *
 * What it does:
 * Writes enum width, registers enum values, then finalizes metadata.
 */
void EBeamParamTypeInfo::Init()
{
  size_ = sizeof(EBeamParam);
  gpg::RType::Init();
  AddEnums();
  Finish();
}
