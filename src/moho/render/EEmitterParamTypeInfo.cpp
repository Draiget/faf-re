#include "moho/render/EEmitterParamTypeInfo.h"

#include <utility>
#include <cstdint>
#include <typeinfo>

#include "moho/render/EEmitterParam.h"

#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
} // namespace

namespace moho
{
  /**
   * Address: 0x00770790 (FUN_00770790, static-init lane)
   * Address: 0x00C01FF0 (FUN_00C01FF0, atexit destructor of the EEmitterParamTypeInfo object; registered by 0x00BDCE60)
   *
   * What it does:
   * Constructs the static descriptor on first call; the constructor is what
   * performs the `PreRegisterRType`, so one construction is the whole
   * registration.
   */
  gpg::REnumType* preregister_EEmitterParamTypeInfo()
  {
    static moho::EEmitterParamTypeInfo sInstance;
    return &sInstance;
  }
} // namespace moho

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
  AddEnum(StripPrefix("EFFECT_POSITION"), std::to_underlying(EFFECT_POSITION));
  AddEnum(StripPrefix("EFFECT_POSITION_X"), std::to_underlying(EFFECT_POSITION_X));
  AddEnum(StripPrefix("EFFECT_POSITION_Y"), std::to_underlying(EFFECT_POSITION_Y));
  AddEnum(StripPrefix("EFFECT_POSITION_Z"), std::to_underlying(EFFECT_POSITION_Z));
  AddEnum(StripPrefix("EFFECT_TICKCOUNT"), std::to_underlying(EFFECT_TICKCOUNT));
  AddEnum(StripPrefix("EFFECT_LIFETIME"), std::to_underlying(EFFECT_LIFETIME));
  AddEnum(StripPrefix("EFFECT_REPEATTIME"), std::to_underlying(EFFECT_REPEATTIME));
  AddEnum(StripPrefix("EFFECT_TICKINCREMENT"), std::to_underlying(EFFECT_TICKINCREMENT));
  AddEnum(StripPrefix("EFFECT_BLENDMODE"), std::to_underlying(EFFECT_BLENDMODE));
  AddEnum(StripPrefix("EFFECT_FRAMECOUNT"), std::to_underlying(EFFECT_FRAMECOUNT));
  AddEnum(StripPrefix("EFFECT_USE_LOCAL_VELOCITY"), std::to_underlying(EFFECT_USE_LOCAL_VELOCITY));
  AddEnum(StripPrefix("EFFECT_USE_LOCAL_ACCELERATION"), std::to_underlying(EFFECT_USE_LOCAL_ACCELERATION));
  AddEnum(StripPrefix("EFFECT_USE_GRAVITY"), std::to_underlying(EFFECT_USE_GRAVITY));
  AddEnum(StripPrefix("EFFECT_ALIGN_ROTATION"), std::to_underlying(EFFECT_ALIGN_ROTATION));
  AddEnum(StripPrefix("EFFECT_INTERPOLATE_EMISSION"), std::to_underlying(EFFECT_INTERPOLATE_EMISSION));
  AddEnum(StripPrefix("EFFECT_TEXTURE_STRIPCOUNT"), std::to_underlying(EFFECT_TEXTURE_STRIPCOUNT));
  AddEnum(StripPrefix("EFFECT_ALIGN_TO_BONE"), std::to_underlying(EFFECT_ALIGN_TO_BONE));
  AddEnum(StripPrefix("EFFECT_SORTORDER"), std::to_underlying(EFFECT_SORTORDER));
  AddEnum(StripPrefix("EFFECT_FLAT"), std::to_underlying(EFFECT_FLAT));
  AddEnum(StripPrefix("EFFECT_SCALE"), std::to_underlying(EFFECT_SCALE));
  AddEnum(StripPrefix("EFFECT_LODCUTOFF"), std::to_underlying(EFFECT_LODCUTOFF));
  AddEnum(StripPrefix("EFFECT_EMITIFVISIBLE"), std::to_underlying(EFFECT_EMITIFVISIBLE));
  AddEnum(StripPrefix("EFFECT_CATCHUPEMIT"), std::to_underlying(EFFECT_CATCHUPEMIT));
  AddEnum(StripPrefix("EFFECT_CREATEIFVISIBLE"), std::to_underlying(EFFECT_CREATEIFVISIBLE));
  AddEnum(StripPrefix("EFFECT_SNAPTOWATERLINE"), std::to_underlying(EFFECT_SNAPTOWATERLINE));
  AddEnum(StripPrefix("EFFECT_ONLYEMITONWATER"), std::to_underlying(EFFECT_ONLYEMITONWATER));
  AddEnum(StripPrefix("EFFECT_PARTICLERESISTANCE"), std::to_underlying(EFFECT_PARTICLERESISTANCE));
  AddEnum(StripPrefix("EFFECT_LASTPARAM"), std::to_underlying(EFFECT_LASTPARAM));
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

// Phase-1 pre-registration: the emitter Lua bindings resolve EEmitterParam
// through gpg::LookupRType (ResolveEEmitterParamType) to translate parameter
// names, so the descriptor must exist before that consumer runs. See
// StaticInitPhase.h.
GPG_PREREGISTER_INIT(
  preregister_EEmitterParamTypeInfo_770790,
  moho::preregister_EEmitterParamTypeInfo
)
