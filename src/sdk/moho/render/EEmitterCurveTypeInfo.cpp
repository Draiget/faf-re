#include "moho/render/EEmitterCurveTypeInfo.h"

#include <cstdint>
#include <typeinfo>

#include "moho/render/EEmitterCurve.h"

#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/StaticTypeInfoStorage.h"

using namespace moho;

namespace
{
  gpg::StaticTypeInfoStorage<moho::EEmitterCurveTypeInfo> gEEmitterCurveTypeInfoStorage{};
} // namespace

namespace moho
{
  /**
   * Address: 0x007704E0 (FUN_007704E0, static-init lane)
   *
   * What it does:
   * Constructs the static descriptor on first call; the constructor is what
   * performs the `PreRegisterRType`, so one construction is the whole
   * registration.
   */
  gpg::REnumType* preregister_EEmitterCurveTypeInfo()
  {
    return &gEEmitterCurveTypeInfoStorage.Ensure();
  }
} // namespace moho

/**
 * Address: 0x007704E0 (FUN_007704E0)
 *
 * What it does:
 * Preregisters the reflected `EEmitterCurve` enum metadata.
 */
EEmitterCurveTypeInfo::EEmitterCurveTypeInfo()
{
  gpg::PreRegisterRType(typeid(EEmitterCurve), this);
}

/**
 * Address: 0x00770570 (FUN_00770570, scalar deleting thunk)
 */
EEmitterCurveTypeInfo::~EEmitterCurveTypeInfo() = default;

/**
 * Address: 0x00770560 (FUN_00770560)
 *
 * What it does:
 * Returns the reflection type name literal for EEmitterCurve.
 */
const char* EEmitterCurveTypeInfo::GetName() const
{
  return "EEmitterCurve";
}

/**
 * Address: 0x007705A0 (FUN_007705A0)
 *
 * What it does:
 * Registers EEmitterCurve enum option names/values.
 */
void EEmitterCurveTypeInfo::AddEnums()
{
  mPrefix = "EMITTER_";
  AddEnum(StripPrefix("EMITTER_XDIR_CURVE"), static_cast<std::int32_t>(EMITTER_XDIR_CURVE));
  AddEnum(StripPrefix("EMITTER_YDIR_CURVE"), static_cast<std::int32_t>(EMITTER_YDIR_CURVE));
  AddEnum(StripPrefix("EMITTER_ZDIR_CURVE"), static_cast<std::int32_t>(EMITTER_ZDIR_CURVE));
  AddEnum(StripPrefix("EMITTER_EMITRATE_CURVE"), static_cast<std::int32_t>(EMITTER_EMITRATE_CURVE));
  AddEnum(StripPrefix("EMITTER_LIFETIME_CURVE"), static_cast<std::int32_t>(EMITTER_LIFETIME_CURVE));
  AddEnum(StripPrefix("EMITTER_VELOCITY_CURVE"), static_cast<std::int32_t>(EMITTER_VELOCITY_CURVE));
  AddEnum(StripPrefix("EMITTER_X_ACCEL_CURVE"), static_cast<std::int32_t>(EMITTER_X_ACCEL_CURVE));
  AddEnum(StripPrefix("EMITTER_Y_ACCEL_CURVE"), static_cast<std::int32_t>(EMITTER_Y_ACCEL_CURVE));
  AddEnum(StripPrefix("EMITTER_Z_ACCEL_CURVE"), static_cast<std::int32_t>(EMITTER_Z_ACCEL_CURVE));
  AddEnum(StripPrefix("EMITTER_RESISTANCE_CURVE"), static_cast<std::int32_t>(EMITTER_RESISTANCE_CURVE));
  AddEnum(StripPrefix("EMITTER_SIZE_CURVE"), static_cast<std::int32_t>(EMITTER_SIZE_CURVE));
  AddEnum(StripPrefix("EMITTER_X_POSITION_CURVE"), static_cast<std::int32_t>(EMITTER_X_POSITION_CURVE));
  AddEnum(StripPrefix("EMITTER_Y_POSITION_CURVE"), static_cast<std::int32_t>(EMITTER_Y_POSITION_CURVE));
  AddEnum(StripPrefix("EMITTER_Z_POSITION_CURVE"), static_cast<std::int32_t>(EMITTER_Z_POSITION_CURVE));
  AddEnum(StripPrefix("EMITTER_BEGINSIZE_CURVE"), static_cast<std::int32_t>(EMITTER_BEGINSIZE_CURVE));
  AddEnum(StripPrefix("EMITTER_ENDSIZE_CURVE"), static_cast<std::int32_t>(EMITTER_ENDSIZE_CURVE));
  AddEnum(StripPrefix("EMITTER_ROTATION_CURVE"), static_cast<std::int32_t>(EMITTER_ROTATION_CURVE));
  AddEnum(StripPrefix("EMITTER_ROTATION_RATE_CURVE"), static_cast<std::int32_t>(EMITTER_ROTATION_RATE_CURVE));
  AddEnum(StripPrefix("EMITTER_FRAMERATE_CURVE"), static_cast<std::int32_t>(EMITTER_FRAMERATE_CURVE));
  AddEnum(StripPrefix("EMITTER_TEXTURESELECTION_CURVE"), static_cast<std::int32_t>(EMITTER_TEXTURESELECTION_CURVE));
  AddEnum(StripPrefix("EMITTER_RAMPSELECTION_CURVE"), static_cast<std::int32_t>(EMITTER_RAMPSELECTION_CURVE));
  AddEnum(StripPrefix("EMITTER_LAST_CURVE"), static_cast<std::int32_t>(EMITTER_LAST_CURVE));
}

/**
 * Address: 0x00770540 (FUN_00770540)
 *
 * What it does:
 * Writes enum width, registers enum values, then finalizes metadata.
 */
void EEmitterCurveTypeInfo::Init()
{
  size_ = sizeof(EEmitterCurve);
  gpg::RType::Init();
  AddEnums();
  Finish();
}

// Phase-1 pre-registration: the emitter Lua bindings resolve EEmitterCurve
// through gpg::LookupRType (ResolveEEmitterCurveType) to translate curve
// names, so the descriptor must exist before that consumer runs. See
// StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_EEmitterCurveTypeInfo_7704e0, moho::preregister_EEmitterCurveTypeInfo)
