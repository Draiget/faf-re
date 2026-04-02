#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/unit/core/IUnit.h"

namespace moho
{
  class EUnitStateTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0055BBA0 (FUN_0055BBA0, Moho::EUnitStateTypeInfo::dtr)
     */
    ~EUnitStateTypeInfo() override;

    /**
     * Address: 0x0055BB90 (FUN_0055BB90, Moho::EUnitStateTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0055BB70 (FUN_0055BB70, Moho::EUnitStateTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x0055BBD0 (FUN_0055BBD0, Moho::EUnitStateTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(EUnitState) == 0x04, "EUnitState size must be 0x04");
  static_assert(sizeof(EUnitStateTypeInfo) == 0x78, "EUnitStateTypeInfo size must be 0x78");

  /**
   * Address: 0x0055BB10 (FUN_0055BB10, preregister_EUnitStateTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `EUnitStateTypeInfo` storage and preregisters
   * RTTI ownership for `EUnitState`.
   */
  [[nodiscard]] gpg::REnumType* preregister_EUnitStateTypeInfo();
} // namespace moho

