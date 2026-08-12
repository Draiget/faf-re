#include "moho/sim/EGenericIconTypeTypeInfo.h"

#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/StaticTypeInfoStorage.h"

namespace
{
  gpg::StaticTypeInfoStorage<moho::EGenericIconTypeTypeInfo> gEGenericIconTypeTypeInfoStorage{};
} // namespace

namespace moho
{
  /**
   * Address: 0x0085B120 (FUN_0085B120, static-init lane)
   *
   * What it does:
   * Constructs the static descriptor on first call; the constructor is what
   * performs the `PreRegisterRType`, so one construction is the whole
   * registration.
   */
  gpg::REnumType* preregister_EGenericIconTypeTypeInfo()
  {
    return &gEGenericIconTypeTypeInfoStorage.Ensure();
  }

  /**
   * Address: 0x0085B120 (FUN_0085B120, Moho::EGenericIconTypeTypeInfo::EGenericIconTypeTypeInfo)
   *
   * What it does:
   * Preregisters the enum type descriptor for `EGenericIconType` with the reflection registry.
   */
  EGenericIconTypeTypeInfo::EGenericIconTypeTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(EGenericIconType), this);
  }

  /**
   * Address: 0x0085B1B0 (FUN_0085B1B0, Moho::EGenericIconTypeTypeInfo::dtr)
   */
  EGenericIconTypeTypeInfo::~EGenericIconTypeTypeInfo() = default;

  /**
   * Address: 0x0085B1A0 (FUN_0085B1A0, Moho::EGenericIconTypeTypeInfo::GetName)
   */
  const char* EGenericIconTypeTypeInfo::GetName() const
  {
    return "EGenericIconType";
  }

  /**
   * Address: 0x0085B180 (FUN_0085B180, Moho::EGenericIconTypeTypeInfo::Init)
   */
  void EGenericIconTypeTypeInfo::Init()
  {
    size_ = sizeof(EGenericIconType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x0085B1E0 (FUN_0085B1E0, Moho::EGenericIconTypeTypeInfo::AddEnums)
   */
  void EGenericIconTypeTypeInfo::AddEnums()
  {
    mPrefix = "GIT_";
    AddEnum(StripPrefix("GIT_Land"), static_cast<std::int32_t>(GIT_Land));
    AddEnum(StripPrefix("GIT_LandHL"), static_cast<std::int32_t>(GIT_LandHL));
    AddEnum(StripPrefix("GIT_Naval"), static_cast<std::int32_t>(GIT_Naval));
    AddEnum(StripPrefix("GIT_NavalHL"), static_cast<std::int32_t>(GIT_NavalHL));
    AddEnum(StripPrefix("GIT_Air"), static_cast<std::int32_t>(GIT_Air));
    AddEnum(StripPrefix("GIT_AirHL"), static_cast<std::int32_t>(GIT_AirHL));
    AddEnum(StripPrefix("GIT_Structure"), static_cast<std::int32_t>(GIT_Structure));
    AddEnum(StripPrefix("GIT_StructureHL"), static_cast<std::int32_t>(GIT_StructureHL));
  }
} // namespace moho

// Phase-1 pre-registration: gpg::RRef_EGenericIconType resolves the enum
// through gpg::LookupRType when it builds a reflected reference, so the
// descriptor must exist before that consumer runs. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_EGenericIconTypeTypeInfo_85b120, moho::preregister_EGenericIconTypeTypeInfo)
