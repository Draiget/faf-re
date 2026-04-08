#include "moho/unit/core/EFireStateTypeInfo.h"

#include <cstdint>

namespace moho
{
  /**
   * Address: 0x0055BA20 (FUN_0055BA20, Moho::EFireStateTypeInfo::dtr)
   */
  EFireStateTypeInfo::~EFireStateTypeInfo() = default;

  /**
   * Address: 0x0055BA10 (FUN_0055BA10, Moho::EFireStateTypeInfo::GetName)
   */
  const char* EFireStateTypeInfo::GetName() const
  {
    return "EFireState";
  }

  /**
   * Address: 0x0055B9F0 (FUN_0055B9F0, Moho::EFireStateTypeInfo::Init)
   */
  void EFireStateTypeInfo::Init()
  {
    size_ = sizeof(EFireState);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x0055BA50 (FUN_0055BA50, Moho::EFireStateTypeInfo::AddEnums)
   */
  void EFireStateTypeInfo::AddEnums()
  {
    mPrefix = "FIRESTATE_";

    AddEnum(StripPrefix("FIRESTATE_Mix"), static_cast<std::int32_t>(FIRESTATE_Mix));
    AddEnum(StripPrefix("FIRESTATE_ReturnFire"), static_cast<std::int32_t>(FIRESTATE_ReturnFire));
    AddEnum(StripPrefix("FIRESTATE_HoldFire"), static_cast<std::int32_t>(FIRESTATE_HoldFire));
    AddEnum(StripPrefix("FIRESTATE_HoldGround"), static_cast<std::int32_t>(FIRESTATE_HoldGround));
  }
} // namespace moho
