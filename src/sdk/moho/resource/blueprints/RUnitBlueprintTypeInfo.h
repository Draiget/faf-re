#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E0EB84
   * COL: 0x00E683A0
   */
  class RUnitBlueprintTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00522940 (FUN_00522940, Moho::RUnitBlueprintTypeInfo::RUnitBlueprintTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RUnitBlueprint`.
     */
    RUnitBlueprintTypeInfo();

    /**
     * Address: 0x00BF36F0 (FUN_00BF36F0, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~RUnitBlueprintTypeInfo() override;

    /**
     * Address: 0x005229D0 (FUN_005229D0)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005229A0 (FUN_005229A0)
     * Slot: 9
     *
     * What it does:
     * Sets `RUnitBlueprint` size, registers `REntityBlueprint` base metadata,
     * and publishes unit-blueprint section fields.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00525820 (FUN_00525820)
     *
     * What it does:
     * Adds `REntityBlueprint` as the reflected base class lane.
     */
    static void AddBaseREntityBlueprint(gpg::RType* typeInfo);

    /**
     * Address: 0x00522A80 (FUN_00522A80)
     *
     * What it does:
     * Registers unit-blueprint section field descriptors and descriptions.
     */
    static void AddFields(gpg::RType* typeInfo);

    /**
     * Address: 0x00525880 (FUN_00525880, gpg::RType::AddField_RUnitBlueprintGeneral_0x17CGeneral)
     *
     * What it does:
     * Appends the `General` section field descriptor (`+0x17C`).
     */
    static gpg::RField* AddFieldGeneral(gpg::RType* typeInfo);

    /**
     * Address: 0x00525900 (FUN_00525900, gpg::RType::AddField_RUnitBlueprintDisplay_0x200Display)
     *
     * What it does:
     * Appends the `Display` section field descriptor (`+0x200`).
     */
    static gpg::RField* AddFieldDisplaySection(gpg::RType* typeInfo);

    /**
     * Address: 0x00525980 (FUN_00525980, gpg::RType::AddField_RUnitBlueprintPhysics_0x278Physics)
     *
     * What it does:
     * Appends the `Physics` section field descriptor (`+0x278`).
     */
    static gpg::RField* AddFieldPhysicsSection(gpg::RType* typeInfo);

    /**
     * Address: 0x00525A00 (FUN_00525A00, gpg::RType::AddField_RUnitBlueprintAir_0x368Air)
     *
     * What it does:
     * Appends the `Air` section field descriptor (`+0x368`).
     */
    static gpg::RField* AddFieldAirSection(gpg::RType* typeInfo);

    /**
     * Address: 0x00525A80 (FUN_00525A80, gpg::RType::AddField_RUnitBlueprintTransport_0x3F8Transport)
     *
     * What it does:
     * Appends the `Transport` section field descriptor (`+0x3F8`).
     */
    static gpg::RField* AddFieldTransportSection(gpg::RType* typeInfo);

    /**
     * Address: 0x00525B00 (FUN_00525B00, gpg::RType::AddField_RUnitBlueprintDefense_0x420Defense)
     *
     * What it does:
     * Appends the `Defense` section field descriptor (`+0x420`).
     */
    static gpg::RField* AddFieldDefenseSection(gpg::RType* typeInfo);

    /**
     * Address: 0x00525B80 (FUN_00525B80, gpg::RType::AddField_RUnitBlueprintAI_0x460AI)
     *
     * What it does:
     * Appends the `AI` section field descriptor (`+0x460`).
     */
    static gpg::RField* AddFieldAiSection(gpg::RType* typeInfo);

    /**
     * Address: 0x00525C00 (FUN_00525C00, gpg::RType::AddField_RUnitBlueprintIntel_0x330Intel)
     *
     * What it does:
     * Appends the `Intel` section field descriptor (`+0x330`).
     */
    static gpg::RField* AddFieldIntelSection(gpg::RType* typeInfo);

    /**
     * Address: 0x00525C80 (FUN_00525C80, gpg::RType::AddField_vector_RUnitBlueprintWeapon_0x4D4Weapons)
     *
     * What it does:
     * Appends the `Weapons` section field descriptor (`+0x4D4`).
     */
    static gpg::RField* AddFieldWeaponSection(gpg::RType* typeInfo);

    /**
     * Address: 0x00525D00 (FUN_00525D00, gpg::RType::AddField_RUnitBlueprintEconomy_0x4E8Economy)
     *
     * What it does:
     * Appends the `Economy` section field descriptor (`+0x4E8`).
     */
    static gpg::RField* AddFieldEconomySection(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x00BC8C10 (FUN_00BC8C10, register_RUnitBlueprintTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RUnitBlueprintTypeInfo`.
   */
  void register_RUnitBlueprintTypeInfo();

  static_assert(sizeof(RUnitBlueprintTypeInfo) == 0x64, "RUnitBlueprintTypeInfo size must be 0x64");
} // namespace moho
