#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class UnitWeaponTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x006D3FB0 (FUN_006D3FB0, ??0UnitWeaponTypeInfo@Moho@@QAE@@Z)
     *
     * What it does:
     * Constructs and preregisters reflection metadata for `UnitWeapon`.
     */
    UnitWeaponTypeInfo();

    /**
     * Address: 0x006D4050 (FUN_006D4050, Moho::UnitWeaponTypeInfo::dtr)
     *
     * What it does:
     * Releases reflected field/base vectors for `UnitWeapon`.
     */
    ~UnitWeaponTypeInfo() override;

    /**
     * Address: 0x006D4040 (FUN_006D4040, Moho::UnitWeaponTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type-name literal for `UnitWeapon`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006D4010 (FUN_006D4010, Moho::UnitWeaponTypeInfo::Init)
     *
     * What it does:
     * Writes size metadata, adds `CScriptEvent` base relationship, and finalizes
     * `UnitWeapon` reflection type.
     */
    void Init() override;

    /**
     * Address: 0x006DD3D0 (FUN_006DD3D0, Moho::UnitWeaponTypeInfo::AddBase_CScriptEvent)
     *
     * What it does:
     * Adds `CScriptEvent` as a reflected base for `UnitWeapon`.
     */
    static void AddBase_CScriptEvent(gpg::RType* typeInfo);
  };

  static_assert(sizeof(UnitWeaponTypeInfo) == 0x64, "UnitWeaponTypeInfo size must be 0x64");

  /**
   * Address: 0x00BFE740 (FUN_00BFE740, sub_BFE740)
   *
   * What it does:
   * Tears down `UnitWeaponTypeInfo` reflected vectors and restores base RTTI lane.
   */
  void cleanup_UnitWeaponTypeInfo();

  /**
   * Address: 0x00BD88D0 (FUN_00BD88D0, register_UnitWeaponTypeInfo)
   *
   * What it does:
   * Forces `UnitWeaponTypeInfo` registration and schedules exit cleanup.
   */
  void register_UnitWeaponTypeInfo();
} // namespace moho
