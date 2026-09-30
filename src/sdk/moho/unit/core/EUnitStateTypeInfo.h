#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/unit/core/IUnit.h"

namespace moho
{
  class EUnitStateTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0055BB10 (FUN_0055BB10, Moho::EUnitStateTypeInfo::EUnitStateTypeInfo)
     *
     * What it does:
     * Preregisters the enum type descriptor for `EUnitState` with the reflection registry.
     */
    EUnitStateTypeInfo();

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
   * Address: 0x0055BB10 (FUN_0055BB10, static-init lane)
   *
   * What it does:
   * Constructs the static descriptor on first call; the constructor is what
   * performs the `PreRegisterRType`, so one construction is the whole
   * registration.
   */
  [[nodiscard]] gpg::REnumType* preregister_EUnitStateTypeInfo();
} // namespace moho
