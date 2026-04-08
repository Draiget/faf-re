#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum EFireState : std::int32_t
  {
    FIRESTATE_Mix = -1,
    FIRESTATE_ReturnFire = 0,
    FIRESTATE_HoldFire = 1,
    FIRESTATE_HoldGround = 2,
  };

  static_assert(sizeof(EFireState) == 0x4, "EFireState size must be 0x4");

  class EFireStateTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0055BA20 (FUN_0055BA20, Moho::EFireStateTypeInfo::dtr)
     */
    ~EFireStateTypeInfo() override;

    /**
     * Address: 0x0055BA10 (FUN_0055BA10, Moho::EFireStateTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0055B9F0 (FUN_0055B9F0, Moho::EFireStateTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x0055BA50 (FUN_0055BA50, Moho::EFireStateTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(EFireStateTypeInfo) == 0x78, "EFireStateTypeInfo size must be 0x78");
} // namespace moho
