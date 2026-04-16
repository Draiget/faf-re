#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  struct CWeaponAttributes;

  /**
   * VFTABLE: 0x00E2E1F8
   * COL: 0x00E87F74
   */
  class CWeaponAttributesTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x006D3640 (FUN_006D3640, ??0CWeaponAttributesTypeInfo@Moho@@QAE@@Z)
     *
     * What it does:
     * Constructs and preregisters reflection metadata for `CWeaponAttributes`.
     */
    CWeaponAttributesTypeInfo();

    /**
     * Address: 0x006D36D0 (FUN_006D36D0, Moho::CWeaponAttributesTypeInfo::dtr)
     *
     * What it does:
     * Releases the reflected type-info payload and its dynamic vectors.
     */
    ~CWeaponAttributesTypeInfo() override;

    /**
     * Address: 0x006D36C0 (FUN_006D36C0, Moho::CWeaponAttributesTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type-name literal for `CWeaponAttributes`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006D36A0 (FUN_006D36A0, Moho::CWeaponAttributesTypeInfo::Init)
     *
     * What it does:
     * Sets reflected `CWeaponAttributes` size metadata and finalizes the type.
     */
    void Init() override;
  };

  static_assert(sizeof(CWeaponAttributesTypeInfo) == 0x64, "CWeaponAttributesTypeInfo size must be 0x64");

} // namespace moho
