#include "moho/sim/EGenericIconTypeTypeInfo.h"

#include <typeinfo>

namespace moho
{
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
