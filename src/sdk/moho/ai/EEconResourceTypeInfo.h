#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum EEconResource : std::int32_t
  {
    ECON_ENERGY = 0,
    ECON_MASS = 1,
  };

  static_assert(sizeof(EEconResource) == 0x4, "EEconResource size must be 0x4");

  class EEconResourceTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00563A40 (FUN_00563A40, Moho::EEconResourceTypeInfo::dtr)
     */
    ~EEconResourceTypeInfo() override;

    /**
     * Address: 0x00563A30 (FUN_00563A30, Moho::EEconResourceTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005639E0 (FUN_005639E0, Moho::EEconResourceTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x00563A70 (FUN_00563A70, Moho::EEconResourceTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(EEconResourceTypeInfo) == 0x78, "EEconResourceTypeInfo size must be 0x78");
} // namespace moho

