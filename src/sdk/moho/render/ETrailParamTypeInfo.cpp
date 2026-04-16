#include "moho/render/ETrailParamTypeInfo.h"

#include <cstdint>
#include <typeinfo>

#include "moho/render/ETrailParam.h"

using namespace moho;

/**
 * Address: 0x00770DD0 (FUN_00770DD0)
 *
 * What it does:
 * Preregisters the reflected `ETrailParam` enum metadata.
 */
ETrailParamTypeInfo::ETrailParamTypeInfo()
{
  gpg::PreRegisterRType(typeid(ETrailParam), this);
}

/**
 * Address: 0x00770E60 (FUN_00770E60, scalar deleting thunk)
 */
ETrailParamTypeInfo::~ETrailParamTypeInfo() = default;

/**
 * Address: 0x00770E50 (FUN_00770E50)
 *
 * What it does:
 * Returns the reflection type name literal for ETrailParam.
 */
const char* ETrailParamTypeInfo::GetName() const
{
  return "ETrailParam";
}

/**
 * Address: 0x00770E90 (FUN_00770E90)
 *
 * What it does:
 * Registers ETrailParam enum option names/values.
 */
void ETrailParamTypeInfo::AddEnums()
{
  mPrefix = "TRAIL_";
  AddEnum(StripPrefix("TRAIL_POSITION"), static_cast<std::int32_t>(TRAIL_POSITION));
  AddEnum(StripPrefix("TRAIL_POSITION_X"), static_cast<std::int32_t>(TRAIL_POSITION_X));
  AddEnum(StripPrefix("TRAIL_POSITION_Y"), static_cast<std::int32_t>(TRAIL_POSITION_Y));
  AddEnum(StripPrefix("TRAIL_POSITION_Z"), static_cast<std::int32_t>(TRAIL_POSITION_Z));
  AddEnum(StripPrefix("TRAIL_LIFETIME"), static_cast<std::int32_t>(TRAIL_LIFETIME));
  AddEnum(StripPrefix("TRAIL_LENGTH"), static_cast<std::int32_t>(TRAIL_LENGTH));
  AddEnum(StripPrefix("TRAIL_SCALE"), static_cast<std::int32_t>(TRAIL_SCALE));
  AddEnum(StripPrefix("TRAIL_LASTPARAM"), static_cast<std::int32_t>(TRAIL_LASTPARAM));
}

/**
 * Address: 0x00770E30 (FUN_00770E30)
 *
 * What it does:
 * Writes enum width, registers enum values, then finalizes metadata.
 */
void ETrailParamTypeInfo::Init()
{
  size_ = sizeof(ETrailParam);
  gpg::RType::Init();
  AddEnums();
  Finish();
}
