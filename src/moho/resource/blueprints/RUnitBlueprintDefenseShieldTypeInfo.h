#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E0EB68
   * COL: 0x00E683E8
   */
  class RUnitBlueprintDefenseShieldTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005217D0 (FUN_005217D0, Moho::RUnitBlueprintDefenseShieldTypeInfo::RUnitBlueprintDefenseShieldTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RUnitBlueprintDefenseShield`.
     */
    RUnitBlueprintDefenseShieldTypeInfo();

    /**
     * Address: 0x00BF3500 (FUN_00BF3500, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~RUnitBlueprintDefenseShieldTypeInfo() override;

    /**
     * Address: 0x00521890 (FUN_00521890)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00521830 (FUN_00521830)
     * Slot: 9
     *
     * What it does:
     * Sets `RUnitBlueprintDefenseShield` size and publishes shield field
     * metadata.
     */
    void Init() override;
  };

  /**
   * Address: 0x00BC8B50 (FUN_00BC8B50, register_RUnitBlueprintDefenseShieldTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RUnitBlueprintDefenseShieldTypeInfo`.
   */
  void register_RUnitBlueprintDefenseShieldTypeInfo();

  static_assert(
    sizeof(RUnitBlueprintDefenseShieldTypeInfo) == 0x64, "RUnitBlueprintDefenseShieldTypeInfo size must be 0x64"
  );
} // namespace moho

